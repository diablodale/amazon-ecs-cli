// Copyright 2015-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/docker/libcompose/config"
	"github.com/docker/libcompose/project"
	"github.com/docker/libcompose/yaml"
	"github.com/stretchr/testify/assert"
)

const (
	portNumber     = 8000
	portMapping    = "8000:8000"
	containerPath  = "/tmp/cache"
	containerPath2 = "/tmp/cache2"
	hostPath       = "./cache"
	namedVolume    = "named_volume"
)

var defaultNetwork = &yaml.Network{
	Name:     "default",
	RealName: "project_default",
}

func TestConvertToTaskDefinition(t *testing.T) {
	name := "mysql"
	cpu := int64(131072) // 128 * 1024
	command := "cmd"
	hostname := "foobarbaz"
	image := "testimage"
	links := []string{"container1"}
	memory := int64(131072) // 128 GiB = 131072 MiB
	memoryReservation := int64(65536)
	privileged := true
	readOnly := true
	securityOpts := []string{"label:type:test_virt"}
	user := "user"
	workingDir := "/var"
	taskRoleArn := "arn:aws:iam::123456789012:role/my_role"

	serviceConfig := &config.ServiceConfig{
		CPUShares:      yaml.StringorInt(cpu),
		Command:        []string{command},
		Hostname:       hostname,
		Image:          image,
		Links:          links,
		MemLimit:       yaml.MemStringorInt(int64(1048576) * memory), //1 MiB = 1048576B
		MemReservation: yaml.MemStringorInt(int64(524288) * memory),
		Networks:       &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
		Privileged:     privileged,
		ReadOnly:       readOnly,
		SecurityOpt:    securityOpts,
		User:           user,
		WorkingDir:     workingDir,
	}

	// convert
	taskDefinition := convertToTaskDefinitionInTest(t, name, nil, serviceConfig, taskRoleArn, "")
	containerDef := *taskDefinition.ContainerDefinitions[0]

	// verify
	if name != aws.StringValue(containerDef.Name) {
		t.Errorf("Expected Name [%s] But was [%s]", name, aws.StringValue(containerDef.Name))
	}
	if cpu != aws.Int64Value(containerDef.Cpu) {
		t.Errorf("Expected cpu [%d] But was [%d]", cpu, aws.Int64Value(containerDef.Cpu))
	}
	if len(containerDef.Command) != 1 || command != aws.StringValue(containerDef.Command[0]) {
		t.Errorf("Expected command [%s] But was [%v]", command, containerDef.Command)
	}
	if !reflect.DeepEqual(securityOpts, aws.StringValueSlice(containerDef.DockerSecurityOptions)) {
		t.Errorf("Expected securityOpt [%v] But was [%v]", securityOpts, aws.StringValueSlice(containerDef.DockerSecurityOptions))
	}
	if hostname != aws.StringValue(containerDef.Hostname) {
		t.Errorf("Expected hostname [%s] But was [%s]", hostname, aws.StringValue(containerDef.Hostname))
	}
	if image != aws.StringValue(containerDef.Image) {
		t.Errorf("Expected Image [%s] But was [%s]", image, aws.StringValue(containerDef.Image))
	}
	if !reflect.DeepEqual(links, aws.StringValueSlice(containerDef.Links)) {
		t.Errorf("Expected links [%v] But was [%v]", links, aws.StringValueSlice(containerDef.Links))
	}
	if memory != aws.Int64Value(containerDef.Memory) {
		t.Errorf("Expected memory [%d] But was [%d]", memory, aws.Int64Value(containerDef.Memory))
	}

	assert.Equal(t, memoryReservation, aws.Int64Value(containerDef.MemoryReservation), "Expected memoryReservation to match")

	assert.Nil(t, containerDef.LinuxParameters.SharedMemorySize, "Expected sharedMemorySize to be null")

	if privileged != aws.BoolValue(containerDef.Privileged) {
		t.Errorf("Expected privileged [%t] But was [%t]", privileged, aws.BoolValue(containerDef.Privileged))
	}
	if readOnly != aws.BoolValue(containerDef.ReadonlyRootFilesystem) {
		t.Errorf("Expected ReadonlyRootFilesystem [%t] But was [%t]", readOnly, aws.BoolValue(containerDef.ReadonlyRootFilesystem))
	}
	if user != aws.StringValue(containerDef.User) {
		t.Errorf("Expected user [%s] But was [%s]", user, aws.StringValue(containerDef.User))
	}
	if workingDir != aws.StringValue(containerDef.WorkingDirectory) {
		t.Errorf("Expected WorkingDirectory [%s] But was [%s]", workingDir, aws.StringValue(containerDef.WorkingDirectory))
	}
	assert.Equal(t, taskRoleArn, aws.StringValue(taskDefinition.TaskRoleArn), "Expected taskRoleArn to match")

	if len(taskDefinition.RequiresCompatibilities) > 0 {
		t.Error("Did not expect RequiresCompatibilities to be set")
	}
	// If no containers are specified as being essential, all containers
	// are marked "essential"
	for _, container := range taskDefinition.ContainerDefinitions {
		assert.True(t, aws.BoolValue(container.Essential), "Expected essential to be true")
	}
}

func TestConvertToTaskDefinitionWithNoSharedMemorySize(t *testing.T) {
	serviceConfig := serviceConfigWithDefaultNetworks()

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]

	assert.Nil(t, containerDef.LinuxParameters.SharedMemorySize, "Expected sharedMemorySize to be null")
}

func TestConvertToTaskDefinitionWithSharedMemorySize(t *testing.T) {
	// Realistically, we expect customers to specify sizes larger than the default of 64M
	expectedMBs := 128
	shmSize := yaml.MemStringorInt(int64(expectedMBs * miB))

	serviceConfig := &config.ServiceConfig{
		ShmSize:  shmSize,
		Networks: &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]

	assert.Equal(t, int64(expectedMBs), aws.Int64Value(containerDef.LinuxParameters.SharedMemorySize), "Expected sharedMemorySize to match")
}

func TestConvertToTaskDefinitionLaunchTypeEmpty(t *testing.T) {
	serviceConfig := serviceConfigWithDefaultNetworks()

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	if len(taskDefinition.RequiresCompatibilities) > 0 {
		t.Error("Did not expect RequiresCompatibilities to be set")
	}
}

func TestConvertToTaskDefinitionLaunchTypeEC2(t *testing.T) {
	serviceConfig := serviceConfigWithDefaultNetworks()

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "EC2")
	if len(taskDefinition.RequiresCompatibilities) != 1 {
		t.Error("Expected exactly one required compatibility to be set.")
	}
	assert.Equal(t, "EC2", aws.StringValue(taskDefinition.RequiresCompatibilities[0]))
}

func TestConvertToTaskDefinitionLaunchTypeFargate(t *testing.T) {
	serviceConfig := serviceConfigWithDefaultNetworks()

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "FARGATE")
	if len(taskDefinition.RequiresCompatibilities) != 1 {
		t.Error("Expected exactly one required compatibility to be set.")
	}
	assert.Equal(t, "FARGATE", aws.StringValue(taskDefinition.RequiresCompatibilities[0]))
}

func TestConvertToTaskDefinitionWithECSParams(t *testing.T) {
	ecsParamsString := `version: 1
task_definition:
  ecs_network_mode: host
  task_role_arn: arn:aws:iam::123456789012:role/my_role`

	content := []byte(ecsParamsString)

	tmpfile, err := ioutil.TempFile("", "ecs-params")
	assert.NoError(t, err, "Could not create ecs fields tempfile")

	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	assert.NoError(t, err, "Could not write data to ecs fields tempfile")

	err = tmpfile.Close()
	assert.NoError(t, err, "Could not close tempfile")

	ecsParamsFileName := tmpfile.Name()
	ecsParams, err := ReadECSParams(ecsParamsFileName)
	assert.NoError(t, err, "Could not read ECS Params file")

	taskDefinition, err := convertToTaskDefWithEcsParamsInTest(t, []string{"mysql", "wordpress"}, nil, serviceConfigWithDefaultNetworks(), "", ecsParams)

	if assert.NoError(t, err) {
		assert.Equal(t, "host", aws.StringValue(taskDefinition.NetworkMode), "Expected network mode to match")
		assert.Equal(t, "arn:aws:iam::123456789012:role/my_role", aws.StringValue(taskDefinition.TaskRoleArn), "Expected task role ARN to match")

		// If no containers are specified as being essential, all
		// containers are marked "essential"
		for _, container := range taskDefinition.ContainerDefinitions {
			assert.True(t, aws.BoolValue(container.Essential), "Expected essential to be true")
		}
	}
}

func TestConvertToTaskDefinition_WithECSParamsAllFields(t *testing.T) {
	ecsParamsString := `version: 1
task_definition:
  ecs_network_mode: host
  task_role_arn: arn:aws:iam::123456789012:role/tweedledee
  services:
    mysql:
      essential: false
  task_size:
    mem_limit: 5Gb
    cpu_limit: 256`

	content := []byte(ecsParamsString)

	tmpfile, err := ioutil.TempFile("", "ecs-params")
	assert.NoError(t, err, "Could not create ecs fields tempfile")

	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	assert.NoError(t, err, "Could not write data to ecs fields tempfile")

	err = tmpfile.Close()
	assert.NoError(t, err, "Could not close tempfile")

	ecsParamsFileName := tmpfile.Name()
	ecsParams, err := ReadECSParams(ecsParamsFileName)
	assert.NoError(t, err, "Could not read ECS Params file")

	taskDefinition, err := convertToTaskDefWithEcsParamsInTest(t, []string{"mysql", "wordpress"}, nil, serviceConfigWithDefaultNetworks(), "", ecsParams)

	containerDefs := taskDefinition.ContainerDefinitions
	mysql := findContainerByName("mysql", containerDefs)

	if assert.NoError(t, err) {
		assert.Equal(t, "host", aws.StringValue(taskDefinition.NetworkMode), "Expected network mode to match")
		assert.Equal(t, "arn:aws:iam::123456789012:role/tweedledee", aws.StringValue(taskDefinition.TaskRoleArn), "Expected task role ARN to match")

		assert.False(t, aws.BoolValue(mysql.Essential), "Expected container with name: '%v' to be false", *mysql.Name)
		assert.Equal(t, "256", aws.StringValue(taskDefinition.Cpu), "Expected CPU to match")
		assert.Equal(t, "5Gb", aws.StringValue(taskDefinition.Memory), "Expected CPU to match")

	}
}

func TestConvertToTaskDefinitionWithECSParams_Essential_OneContainer(t *testing.T) {
	ecsParamsString := `version: 1
task_definition:
  services:
    mysql:
      essential: false`

	content := []byte(ecsParamsString)

	tmpfile, err := ioutil.TempFile("", "ecs-params")
	assert.NoError(t, err, "Could not create ecs fields tempfile")

	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	assert.NoError(t, err, "Could not write data to ecs fields tempfile")

	err = tmpfile.Close()
	assert.NoError(t, err, "Could not close tempfile")

	ecsParamsFileName := tmpfile.Name()
	ecsParams, err := ReadECSParams(ecsParamsFileName)
	assert.NoError(t, err, "Could not read ECS Params file")

	taskDefinition, err := convertToTaskDefWithEcsParamsInTest(t, []string{"mysql", "wordpress"}, nil, serviceConfigWithDefaultNetworks(), "", ecsParams)

	containerDefs := taskDefinition.ContainerDefinitions
	mysql := findContainerByName("mysql", containerDefs)
	wordpress := findContainerByName("wordpress", containerDefs)

	if assert.NoError(t, err) {
		assert.False(t, aws.BoolValue(mysql.Essential), "Expected container with name: '%v' to be false", *mysql.Name)
		assert.True(t, aws.BoolValue(wordpress.Essential), "Expected container with name: '%v' to be true", *wordpress.Name)
	}
}

func TestConvertToTaskDefinitionWithECSParams_EssentialExplicitlyMarkedTrue(t *testing.T) {
	ecsParamsString := `version: 1
task_definition:
  services:
    mysql:
      essential: true
    wordpress:
      essential: true`

	content := []byte(ecsParamsString)

	tmpfile, err := ioutil.TempFile("", "ecs-params")
	assert.NoError(t, err, "Could not create ecs fields tempfile")

	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	assert.NoError(t, err, "Could not write data to ecs fields tempfile")

	err = tmpfile.Close()
	assert.NoError(t, err, "Could not close tempfile")

	ecsParamsFileName := tmpfile.Name()
	ecsParams, err := ReadECSParams(ecsParamsFileName)
	assert.NoError(t, err, "Could not read ECS Params file")

	taskDefinition, err := convertToTaskDefWithEcsParamsInTest(t, []string{"mysql", "wordpress"}, nil, serviceConfigWithDefaultNetworks(), "", ecsParams)

	containerDefs := taskDefinition.ContainerDefinitions
	mysql := findContainerByName("mysql", containerDefs)
	wordpress := findContainerByName("wordpress", containerDefs)

	if assert.NoError(t, err) {
		assert.True(t, aws.BoolValue(mysql.Essential), "Expected container with name: '%v' to be true", *mysql.Name)
		assert.True(t, aws.BoolValue(wordpress.Essential), "Expected container with name: '%v' to be true", *wordpress.Name)
	}
}

func TestConvertToTaskDefinitionWithECSParams_EssentialExplicitlyMarked(t *testing.T) {
	ecsParamsString := `version: 1
task_definition:
  services:
    mysql:
      essential: false
    wordpress:
      essential: true`

	content := []byte(ecsParamsString)

	tmpfile, err := ioutil.TempFile("", "ecs-params")
	assert.NoError(t, err, "Could not create ecs fields tempfile")

	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	assert.NoError(t, err, "Could not write data to ecs fields tempfile")

	err = tmpfile.Close()
	assert.NoError(t, err, "Could not close tempfile")

	ecsParamsFileName := tmpfile.Name()
	ecsParams, err := ReadECSParams(ecsParamsFileName)
	assert.NoError(t, err, "Could not read ECS Params file")

	taskDefinition, err := convertToTaskDefWithEcsParamsInTest(t, []string{"mysql", "wordpress"}, nil, serviceConfigWithDefaultNetworks(), "", ecsParams)

	containerDefs := taskDefinition.ContainerDefinitions
	mysql := findContainerByName("mysql", containerDefs)
	wordpress := findContainerByName("wordpress", containerDefs)

	if assert.NoError(t, err) {
		assert.False(t, aws.BoolValue(mysql.Essential), "Expected container with name: '%v' to be false", *mysql.Name)
		assert.True(t, aws.BoolValue(wordpress.Essential), "Expected container with name: '%v' to be true", *wordpress.Name)
	}
}

func TestConvertToTaskDefinitionWithECSParams_EssentialBlankForOneService(t *testing.T) {
	ecsParamsString := `version: 1
task_definition:
  ecs_network_mode: host
  task_role_arn: arn:aws:iam::123456789012:role/my_role
  services:
    wordpress:`

	content := []byte(ecsParamsString)

	tmpfile, err := ioutil.TempFile("", "ecs-params")
	assert.NoError(t, err, "Could not create ecs fields tempfile")

	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	assert.NoError(t, err, "Could not write data to ecs fields tempfile")

	err = tmpfile.Close()
	assert.NoError(t, err, "Could not close tempfile")

	ecsParamsFileName := tmpfile.Name()
	ecsParams, err := ReadECSParams(ecsParamsFileName)
	assert.NoError(t, err, "Could not read ECS Params file")

	taskDefinition, err := convertToTaskDefWithEcsParamsInTest(t, []string{"mysql", "wordpress"}, nil, serviceConfigWithDefaultNetworks(), "", ecsParams)

	containerDefs := taskDefinition.ContainerDefinitions
	mysql := findContainerByName("mysql", containerDefs)
	wordpress := findContainerByName("wordpress", containerDefs)

	if assert.NoError(t, err) {
		assert.True(t, aws.BoolValue(mysql.Essential), "Expected container with name: '%v' to be true", *mysql.Name)
		assert.False(t, aws.BoolValue(wordpress.Essential), "Expected container with name: '%v' to be false", *wordpress.Name)
	}
}

func TestConvertToTaskDefinitionWithECSParams_EssentialBlankForAllServices(t *testing.T) {
	ecsParamsString := `version: 1
task_definition:
  ecs_network_mode: host
  task_role_arn: arn:aws:iam::123456789012:role/my_role
  services:
    mysql:
    wordpress:`

	content := []byte(ecsParamsString)

	tmpfile, err := ioutil.TempFile("", "ecs-params")
	assert.NoError(t, err, "Could not create ecs fields tempfile")

	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	assert.NoError(t, err, "Could not write data to ecs fields tempfile")

	err = tmpfile.Close()
	assert.NoError(t, err, "Could not close tempfile")

	ecsParamsFileName := tmpfile.Name()
	ecsParams, err := ReadECSParams(ecsParamsFileName)
	assert.NoError(t, err, "Could not read ECS Params file")

	_, err = convertToTaskDefWithEcsParamsInTest(t, []string{"mysql", "wordpress"}, nil, serviceConfigWithDefaultNetworks(), "", ecsParams)

	// At least one container must be marked essential
	assert.Error(t, err)
}

func TestConvertToTaskDefinitionWithECSParams_AllContainersMarkedNotEssential(t *testing.T) {
	ecsParamsString := `version: 1
task_definition:
  services:
    mysql:
      essential: false
    wordpress:
      essential: false`

	content := []byte(ecsParamsString)

	tmpfile, err := ioutil.TempFile("", "ecs-params")
	assert.NoError(t, err, "Could not create ecs fields tempfile")

	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	assert.NoError(t, err, "Could not write data to ecs fields tempfile")

	err = tmpfile.Close()
	assert.NoError(t, err, "Could not close tempfile")

	ecsParamsFileName := tmpfile.Name()
	ecsParams, err := ReadECSParams(ecsParamsFileName)
	assert.NoError(t, err, "Could not read ECS Params file")

	_, err = convertToTaskDefWithEcsParamsInTest(t, []string{"mysql", "wordpress"}, nil, serviceConfigWithDefaultNetworks(), "", ecsParams)

	// At least one container must be marked essential
	assert.Error(t, err)
}

func TestConvertToTaskDefinitionWithECSParamsAndTaskRoleArnFlag(t *testing.T) {
	ecsParamsString := `version: 1
task_definition:
  ecs_network_mode: host
  task_role_arn: arn:aws:iam::123456789012:role/tweedledee`

	content := []byte(ecsParamsString)

	tmpfile, err := ioutil.TempFile("", "ecs-params")
	assert.NoError(t, err, "Could not create ecs fields tempfile")

	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	assert.NoError(t, err, "Could not write data to ecs fields tempfile")

	err = tmpfile.Close()
	assert.NoError(t, err, "Could not close tempfile")

	ecsParamsFileName := tmpfile.Name()
	ecsParams, err := ReadECSParams(ecsParamsFileName)
	assert.NoError(t, err, "Could not read ECS Params file")

	taskRoleArn := "arn:aws:iam::123456789012:role/tweedledum"

	taskDefinition, err := convertToTaskDefWithEcsParamsInTest(t, []string{"mysql", "wordpress"}, nil, serviceConfigWithDefaultNetworks(), taskRoleArn, ecsParams)

	if assert.NoError(t, err) {
		assert.Equal(t, "host", aws.StringValue(taskDefinition.NetworkMode), "Expected network mode to match")
		assert.Equal(t, "arn:aws:iam::123456789012:role/tweedledum", aws.StringValue(taskDefinition.TaskRoleArn), "Expected task role arn to match")
	}
}

func TestConvertToTaskDefinition_WithTaskSize(t *testing.T) {
	ecsParamsString := `version: 1
task_definition:
  task_size:
    mem_limit: 10MB
    cpu_limit: 200`

	content := []byte(ecsParamsString)

	tmpfile, err := ioutil.TempFile("", "ecs-params")
	assert.NoError(t, err, "Could not create ecs fields tempfile")

	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write(content)
	assert.NoError(t, err, "Could not write data to ecs fields tempfile")

	err = tmpfile.Close()
	assert.NoError(t, err, "Could not close tempfile")

	ecsParamsFileName := tmpfile.Name()
	ecsParams, err := ReadECSParams(ecsParamsFileName)
	assert.NoError(t, err, "Could not read ECS Params file")

	taskDefinition, err := convertToTaskDefWithEcsParamsInTest(t, []string{"mysql", "wordpress"}, nil, serviceConfigWithDefaultNetworks(), "", ecsParams)

	if assert.NoError(t, err) {
		assert.Equal(t, "200", aws.StringValue(taskDefinition.Cpu), "Expected CPU to match")
		assert.Equal(t, "10MB", aws.StringValue(taskDefinition.Memory), "Expected CPU to match")

	}
}

func TestConvertToTaskDefinitionWithDnsSearch(t *testing.T) {
	dnsSearchDomains := []string{"search.example.com"}

	serviceConfig := &config.ServiceConfig{
		DNSSearch: dnsSearchDomains,
		Networks:  &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]
	if !reflect.DeepEqual(dnsSearchDomains, aws.StringValueSlice(containerDef.DnsSearchDomains)) {
		t.Errorf("Expected dnsSearchDomains [%v] But was [%v]", dnsSearchDomains,
			aws.StringValueSlice(containerDef.DnsSearchDomains))
	}
}

func TestConvertToTaskDefinitionWithDnsServers(t *testing.T) {
	dnsServer := "1.2.3.4"

	serviceConfig := &config.ServiceConfig{
		DNS:      []string{dnsServer},
		Networks: &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]
	if !reflect.DeepEqual([]string{dnsServer}, aws.StringValueSlice(containerDef.DnsServers)) {
		t.Errorf("Expected dnsServer [%s] But was [%v]", dnsServer, aws.StringValueSlice(containerDef.DnsServers))
	}
}

func TestConvertToTaskDefinitionWithDockerLabels(t *testing.T) {
	dockerLabels := map[string]string{
		"label1":         "",
		"com.foo.label2": "value",
	}

	serviceConfig := &config.ServiceConfig{
		Labels:   dockerLabels,
		Networks: &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]
	if !reflect.DeepEqual(dockerLabels, aws.StringValueMap(containerDef.DockerLabels)) {
		t.Errorf("Expected dockerLabels [%v] But was [%v]", dockerLabels, aws.StringValueMap(containerDef.DockerLabels))
	}
}

func TestConvertToTaskDefinitionWithEnv(t *testing.T) {
	envKey := "rails_env"
	envValue := "development"
	env := envKey + "=" + envValue
	serviceConfig := &config.ServiceConfig{
		Environment: []string{env},
		Networks:    &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]

	if envKey != aws.StringValue(containerDef.Environment[0].Name) ||
		envValue != aws.StringValue(containerDef.Environment[0].Value) {
		t.Errorf("Expected env [%s] But was [%v]", env, containerDef.Environment)
	}
}

func TestConvertToTaskDefinitionWithEnvFromShell(t *testing.T) {
	envKey1 := "rails_env"
	envValue1 := "development"
	env := envKey1 + "=" + envValue1
	envKey2 := "port"

	serviceConfig := &config.ServiceConfig{
		Environment: []string{envKey1, envKey2 + "="},
		Networks:    &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	os.Setenv(envKey1, envValue1)
	defer func() {
		os.Unsetenv(envKey1)
	}()

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]

	if containerDef.Environment == nil || len(containerDef.Environment) != 2 {
		t.Fatalf("Expected non empty Environment, but was [%v]", containerDef.Environment)
	}

	if envKey1 != aws.StringValue(containerDef.Environment[0].Name) ||
		envValue1 != aws.StringValue(containerDef.Environment[0].Value) {
		t.Errorf("Expected env [%s] But was [%v]", env, containerDef.Environment)
	}

	// since envKey2 couldn't be resolved, value should be set to an empty string
	if envKey2 != aws.StringValue(containerDef.Environment[1].Name) ||
		"" != aws.StringValue(containerDef.Environment[1].Value) {
		t.Errorf("Expected env [%s] But was [%v]", envKey2, containerDef.Environment)
	}
}

func TestConvertToTaskDefinitionWithPortMappings(t *testing.T) {
	serviceConfig := &config.ServiceConfig{
		Ports:    []string{portMapping},
		Networks: &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]
	verifyPortMapping(t, containerDef.PortMappings[0], portNumber, portNumber, ecs.TransportProtocolTcp)
}

func TestConvertToTaskDefinitionWithVolumesFrom(t *testing.T) {
	// compose file format v2
	setupAndTestVolumesFrom(t, "service_name", "service_name", false)
	setupAndTestVolumesFrom(t, "service_name:ro", "service_name", true)
	setupAndTestVolumesFrom(t, "service_name:rw", "service_name", false)

	setupAndTestVolumesFrom(t, "container:container_name", "container_name", false)
	setupAndTestVolumesFrom(t, "container:container_name:ro", "container_name", true)
	setupAndTestVolumesFrom(t, "container:container_name:rw", "container_name", false)

	// compose file format v1
	setupAndTestVolumesFrom(t, "container_name", "container_name", false)
	setupAndTestVolumesFrom(t, "container_name:ro", "container_name", true)
	setupAndTestVolumesFrom(t, "container_name:rw", "container_name", false)
}

func setupAndTestVolumesFrom(t *testing.T, volume, sourceContainer string, readOnly bool) {
	serviceConfig := &config.ServiceConfig{
		VolumesFrom: []string{volume},
		Networks:    &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}
	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]
	verifyVolumeFrom(t, containerDef.VolumesFrom[0], sourceContainer, readOnly)
}

func TestConvertToTaskDefinitionWithExtraHosts(t *testing.T) {
	hostname := "test.local"
	ipAddress := "127.10.10.10"

	extraHost := hostname + ":" + ipAddress
	serviceConfig := &config.ServiceConfig{
		ExtraHosts: []string{extraHost},
		Networks:   &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]
	verifyExtraHost(t, containerDef.ExtraHosts[0], hostname, ipAddress)
}

func TestConvertToTaskDefinitionWithLogConfiguration(t *testing.T) {
	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfigWithDefaultNetworks(), "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]

	if containerDef.LogConfiguration != nil {
		t.Errorf("Expected empty log configuration. But was [%v]", containerDef.LogConfiguration)
	}

	logDriver := "json-file"
	logOpts := map[string]string{
		"max-file": "50",
		"max-size": "50k",
	}
	serviceConfig := &config.ServiceConfig{
		Logging: config.Log{
			Driver:  logDriver,
			Options: logOpts,
		},
		Networks: &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition = convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef = *taskDefinition.ContainerDefinitions[0]
	if logDriver != aws.StringValue(containerDef.LogConfiguration.LogDriver) {
		t.Errorf("Expected Log driver [%s]. But was [%s]", logDriver, aws.StringValue(containerDef.LogConfiguration.LogDriver))
	}
	if !reflect.DeepEqual(logOpts, aws.StringValueMap(containerDef.LogConfiguration.Options)) {
		t.Errorf("Expected Log options [%v]. But was [%v]", logOpts, aws.StringValueMap(containerDef.LogConfiguration.Options))
	}
}

func TestConvertToTaskDefinitionWithUlimits(t *testing.T) {
	softLimit := int64(1024)
	typeName := "nofile"
	basicType := yaml.NewUlimit(typeName, softLimit, softLimit) // "nofile=1024"
	serviceConfig := &config.ServiceConfig{
		Ulimits:  yaml.Ulimits{Elements: []yaml.Ulimit{basicType}},
		Networks: &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]
	verifyUlimit(t, containerDef.Ulimits[0], typeName, softLimit, softLimit)
}

func TestConvertToTaskDefinitionWithVolumes(t *testing.T) {
	volume := yaml.Volume{Source: hostPath, Destination: containerPath}
	volumesFrom := []string{"container1"}

	serviceConfig := &config.ServiceConfig{
		Volumes:     &yaml.Volumes{Volumes: []*yaml.Volume{&volume}},
		VolumesFrom: volumesFrom,
		Networks:    &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]

	if len(volumesFrom) != len(containerDef.VolumesFrom) ||
		volumesFrom[0] != aws.StringValue(containerDef.VolumesFrom[0].SourceContainer) {
		t.Errorf("Expected volumesFrom [%v] But was [%v]", volumesFrom, containerDef.VolumesFrom)
	}
	volumeDef := *taskDefinition.Volumes[0]
	mountPoint := *containerDef.MountPoints[0]
	if hostPath != aws.StringValue(volumeDef.Host.SourcePath) {
		t.Errorf("Expected HostSourcePath [%s] But was [%s]", hostPath, aws.StringValue(volumeDef.Host.SourcePath))
	}
	if containerPath != aws.StringValue(mountPoint.ContainerPath) {
		t.Errorf("Expected containerPath [%s] But was [%s]", containerPath, aws.StringValue(mountPoint.ContainerPath))
	}
	if aws.StringValue(volumeDef.Name) != aws.StringValue(mountPoint.SourceVolume) {
		t.Errorf("Expected volume name to match. "+
			"Got Volume.Name=[%s] And MountPoint.SourceVolume=[%s]",
			aws.StringValue(volumeDef.Name), aws.StringValue(mountPoint.SourceVolume))
	}
}

func TestConvertToTaskDefinitionWithNamedVolume(t *testing.T) {
	volume := yaml.Volume{Source: namedVolume, Destination: containerPath}

	serviceConfig := &config.ServiceConfig{
		Volumes:  &yaml.Volumes{Volumes: []*yaml.Volume{&volume}},
		Networks: &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", &config.VolumeConfig{}, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]

	volumeDef := *taskDefinition.Volumes[0]
	mountPoint := *containerDef.MountPoints[0]
	if volumeDef.Host != nil {
		t.Errorf("Expected volume host to be nil But was [%s]", volumeDef.Host)
	}
	if containerPath != aws.StringValue(mountPoint.ContainerPath) {
		t.Errorf("Expected containerPath [%s] But was [%s]", containerPath, aws.StringValue(mountPoint.ContainerPath))
	}
	if aws.StringValue(volumeDef.Name) != aws.StringValue(mountPoint.SourceVolume) {
		t.Errorf("Expected volume name to match. "+
			"Got Volume.Name=[%s] And MountPoint.SourceVolume=[%s]",
			aws.StringValue(volumeDef.Name), aws.StringValue(mountPoint.SourceVolume))
	}
}

func TestConvertToTaskDefinitionWithTmpfs(t *testing.T) {
	tmpfs := []string{"/run:rw,noexec,nosuid,size=65536k", "/foo:size=1gb", "/bar:size=1gb,rw,runbindable"}

	serviceConfig := &config.ServiceConfig{
		Tmpfs: tmpfs,
	}

	taskDefinition := convertToTaskDefinitionInTest(t, "name", nil, serviceConfig, "", "")
	containerDef := *taskDefinition.ContainerDefinitions[0]
	tmpfsMounts := containerDef.LinuxParameters.Tmpfs
	mount1 := tmpfsMounts[0]
	mount2 := tmpfsMounts[1]
	mount3 := tmpfsMounts[2]

	assert.Equal(t, "/run", aws.StringValue(mount1.ContainerPath))
	assert.Equal(t, []string{"rw", "noexec", "nosuid"}, aws.StringValueSlice(mount1.MountOptions))
	assert.Equal(t, int64(64), aws.Int64Value(mount1.Size))

	assert.Equal(t, "/foo", aws.StringValue(mount2.ContainerPath))
	assert.Equal(t, []string{}, aws.StringValueSlice(mount2.MountOptions))
	assert.Equal(t, int64(1024), aws.Int64Value(mount2.Size))

	assert.Equal(t, "/bar", aws.StringValue(mount3.ContainerPath))
	assert.Equal(t, []string{"rw", "runbindable"}, aws.StringValueSlice(mount3.MountOptions))
	assert.Equal(t, int64(1024), aws.Int64Value(mount3.Size))
}

func TestConvertToTmpfs_NoPath(t *testing.T) {
	tmpfs := []string{"size=65536k"}
	_, err := ConvertToTmpfs(tmpfs)

	assert.Error(t, err)
}

func TestConvertToTmpfs_BadOptionFormat(t *testing.T) {
	tmpfs := []string{"/run,size=65536k"}
	_, err := ConvertToTmpfs(tmpfs)

	assert.Error(t, err)
}

func TestConvertToTmpfs_NoSize(t *testing.T) {
	tmpfs := []string{"/run"}
	_, err := ConvertToTmpfs(tmpfs)

	assert.Error(t, err)
}

func TestConvertToTmpfs_WithOptionsNoSize(t *testing.T) {
	tmpfs := []string{"/run:rw"}
	_, err := ConvertToTmpfs(tmpfs)

	assert.Error(t, err)
}

func TestConvertToTmpfs_WithMalformedSize(t *testing.T) {
	tmpfs := []string{"/run:1gb"}
	_, err := ConvertToTmpfs(tmpfs)

	assert.Error(t, err)
}

func TestConvertToPortMappings(t *testing.T) {
	implicitTcp := portMapping                      // 8000:8000
	explicitTcp := portMapping + "/tcp"             // "8000:8000/tcp"
	udpPort := portMapping + "/udp"                 // "8000:8000/udp"
	containerPortOnly := strconv.Itoa(portNumber)   // "8000"
	portWithIpAddress := "127.0.0.1:" + portMapping // "127.0.0.1:8000:8000"

	portMappingsIn := []string{implicitTcp, explicitTcp, udpPort, containerPortOnly, portWithIpAddress}

	portMappingsOut, err := ConvertToPortMappings("test", portMappingsIn)
	if err != nil {
		t.Errorf("Expected to convert [%v] portMappings without errors. But got [%v]", portMappingsIn, err)
	}
	if len(portMappingsIn) != len(portMappingsOut) {
		t.Errorf("Incorrect conversion. Input [%v] Output [%v]", portMappingsIn, portMappingsOut)
	}
	verifyPortMapping(t, portMappingsOut[0], portNumber, portNumber, ecs.TransportProtocolTcp)
	verifyPortMapping(t, portMappingsOut[1], portNumber, portNumber, ecs.TransportProtocolTcp)
	verifyPortMapping(t, portMappingsOut[2], portNumber, portNumber, ecs.TransportProtocolUdp)
	verifyPortMapping(t, portMappingsOut[3], 0, portNumber, ecs.TransportProtocolTcp)
	verifyPortMapping(t, portMappingsOut[4], portNumber, portNumber, ecs.TransportProtocolTcp)
}

func verifyPortMapping(t *testing.T, output *ecs.PortMapping, hostPort, containerPort int64, protocol string) {
	if protocol != *output.Protocol {
		t.Errorf("Expected protocol [%s] But was [%s]", protocol, *output.Protocol)
	}
	if hostPort != *output.HostPort {
		t.Errorf("Expected hostPort [%d] But was [%d]", hostPort, *output.HostPort)
	}
	if containerPort != *output.ContainerPort {
		t.Errorf("Expected containerPort [%d] But was [%d]", containerPort, *output.ContainerPort)
	}
}

func TestConvertToMountPoints(t *testing.T) {
	onlyContainerPath := yaml.Volume{Destination: containerPath}
	onlyContainerPath2 := yaml.Volume{Destination: containerPath2}
	hostAndContainerPath := yaml.Volume{Source: hostPath, Destination: containerPath} // "./cache:/tmp/cache"
	onlyContainerPathWithRO := yaml.Volume{Destination: containerPath, AccessMode: "ro"}
	hostAndContainerPathWithRO := yaml.Volume{Source: hostPath, Destination: containerPath, AccessMode: "ro"} // "./cache:/tmp/cache:ro"
	hostAndContainerPathWithRW := yaml.Volume{Source: hostPath, Destination: containerPath, AccessMode: "rw"}
	namedVolumeAndContainerPath := yaml.Volume{Source: namedVolume, Destination: containerPath}

	volumes := &volumes{
		volumeWithHost:  make(map[string]string), // map with key:=hostSourcePath value:=VolumeName
		volumeEmptyHost: []string{namedVolume},   // Declare one volume with an empty host
	}

	// Valid inputs with host and container paths set
	mountPointsIn := yaml.Volumes{Volumes: []*yaml.Volume{&onlyContainerPath, &onlyContainerPath2, &hostAndContainerPath,
		&onlyContainerPathWithRO, &hostAndContainerPathWithRO, &hostAndContainerPathWithRW, &namedVolumeAndContainerPath}}

	mountPointsOut, err := ConvertToMountPoints(&mountPointsIn, volumes)
	if err != nil {
		t.Fatalf("Expected to convert [%v] mountPoints without errors. But got [%v]", mountPointsIn, err)
	}
	if len(mountPointsIn.Volumes) != len(mountPointsOut) {
		t.Errorf("Incorrect conversion. Input [%v] Output [%v]", mountPointsIn, mountPointsOut)
	}

	verifyMountPoint(t, mountPointsOut[0], volumes, "", containerPath, false, 1)  // 1 is the counter for the first volume with an empty host path
	verifyMountPoint(t, mountPointsOut[1], volumes, "", containerPath2, false, 2) // 2 is the counter for the second volume with an empty host path
	verifyMountPoint(t, mountPointsOut[2], volumes, hostPath, containerPath, false, 2)
	verifyMountPoint(t, mountPointsOut[3], volumes, "", containerPath, true, 3) // 3 is the counter for the third volume with an empty host path
	verifyMountPoint(t, mountPointsOut[4], volumes, hostPath, containerPath, true, 3)
	verifyMountPoint(t, mountPointsOut[5], volumes, hostPath, containerPath, false, 3)
	verifyMountPoint(t, mountPointsOut[6], volumes, namedVolume, containerPath, false, 3)

	if mountPointsOut[0].SourceVolume == mountPointsOut[1].SourceVolume {
		t.Errorf("Expected volume %v (onlyContainerPath) and %v (onlyContainerPath2) to be different", mountPointsOut[0].SourceVolume, mountPointsOut[1].SourceVolume)
	}

	if mountPointsOut[1].SourceVolume == mountPointsOut[3].SourceVolume {
		t.Errorf("Expected volume %v (onlyContainerPath2) and %v (onlyContainerPathWithRO) to be different", mountPointsOut[0].SourceVolume, mountPointsOut[1].SourceVolume)
	}

	// Invalid access mode input
	hostAndContainerPathWithIncorrectAccess := yaml.Volume{Source: hostPath, Destination: containerPath, AccessMode: "readonly"}
	mountPointsIn = yaml.Volumes{Volumes: []*yaml.Volume{&hostAndContainerPathWithIncorrectAccess}}
	mountPointsOut, err = ConvertToMountPoints(&mountPointsIn, volumes)
	if err == nil {
		t.Errorf("Expected to get error for mountPoint[%s] but didn't.", hostAndContainerPathWithIncorrectAccess)
	}

	mountPointsOut, err = ConvertToMountPoints(nil, volumes)
	if err != nil {
		t.Fatalf("Expected to convert nil mountPoints without errors. But got [%v]", err)
	}
	if len(mountPointsOut) != 0 {
		t.Errorf("Incorrect conversion. Input nil Output [%v]", mountPointsOut)
	}
}

func verifyMountPoint(t *testing.T, output *ecs.MountPoint, volumes *volumes,
	source, containerPath string, readonly bool, EmptyHostCtr int) {
	sourceVolume := ""
	if containerPath != *output.ContainerPath {
		t.Errorf("Expected containerPath [%s] But was [%s]", containerPath, *output.ContainerPath)
	}
	if source == "" {
		sourceVolume = volumes.volumeEmptyHost[EmptyHostCtr]
	} else if project.IsNamedVolume(source) {
		sourceVolume = source
	} else {
		sourceVolume = volumes.volumeWithHost[source]
	}
	if sourceVolume != *output.SourceVolume {
		t.Errorf("Expected sourceVolume [%s] But was [%s]", sourceVolume, *output.SourceVolume)
	}
	if readonly != *output.ReadOnly {
		t.Errorf("Expected readonly [%v] But was [%v]", readonly, *output.ReadOnly)
	}
}

func TestConvertToExtraHosts(t *testing.T) {
	hostname := "test.local"
	ipAddress := "127.10.10.10"

	extraHost := hostname + ":" + ipAddress

	extraHostsIn := []string{extraHost}
	extraHostsOut, err := ConvertToExtraHosts(extraHostsIn)
	if err != nil {
		t.Errorf("Expected to convert [%v] extra hosts without errors. But got [%v]", extraHostsIn, err)
	}
	if len(extraHostsIn) != len(extraHostsOut) {
		t.Errorf("Incorrect conversion. Input [%v] Output [%v]", extraHostsIn, extraHostsOut)
	}
	verifyExtraHost(t, extraHostsOut[0], hostname, ipAddress)

	incorrectHost := hostname + "=" + ipAddress
	_, err = ConvertToExtraHosts([]string{incorrectHost})
	if err == nil {
		t.Errorf("Expected to get formatting error for extraHost=[%s], but got none", incorrectHost)
	}

	extraHostWithPort := fmt.Sprintf("%s:%s:%d", hostname, ipAddress, portNumber)
	_, err = ConvertToExtraHosts([]string{extraHostWithPort})
	if err == nil {
		t.Errorf("Expected to get formatting error for extraHost=[%s], but got none", extraHostWithPort)
	}

}

func verifyExtraHost(t *testing.T, output *ecs.HostEntry, hostname, ipAddress string) {
	if hostname != aws.StringValue(output.Hostname) {
		t.Errorf("Expected hostname [%s] But was [%s]", hostname, aws.StringValue(output.Hostname))
	}
	if ipAddress != aws.StringValue(output.IpAddress) {
		t.Errorf("Expected ipAddress [%s] But was [%s]", ipAddress, aws.StringValue(output.IpAddress))
	}
}

func verifyVolumeFrom(t *testing.T, output *ecs.VolumeFrom, containerName string, readOnly bool) {
	if containerName != aws.StringValue(output.SourceContainer) {
		t.Errorf("Expected SourceContainer [%s] But was [%s]", containerName, aws.StringValue(output.SourceContainer))
	}
	if readOnly != aws.BoolValue(output.ReadOnly) {
		t.Errorf("Expected ReadOnly [%t] But was [%t]", readOnly, aws.BoolValue(output.ReadOnly))
	}
}

func TestConvertToUlimits(t *testing.T) {
	softLimit := int64(1024)
	hardLimit := int64(2048)
	typeName := "nofile"
	basicType := yaml.NewUlimit(typeName, softLimit, softLimit)         // "nofile=1024"
	typeWithHardLimit := yaml.NewUlimit(typeName, softLimit, hardLimit) // "nofile=1024:2048"

	ulimitsIn := yaml.Ulimits{
		Elements: []yaml.Ulimit{basicType, typeWithHardLimit},
	}
	ulimitsOut, err := ConvertToULimits(ulimitsIn)
	if err != nil {
		t.Errorf("Expected to convert [%v] ulimits without errors. But got [%v]", ulimitsIn, err)
	}
	if len(ulimitsIn.Elements) != len(ulimitsOut) {
		t.Errorf("Incorrect conversion. Input [%v] Output [%v]", ulimitsIn, ulimitsOut)
	}
	verifyUlimit(t, ulimitsOut[0], typeName, softLimit, softLimit)
	verifyUlimit(t, ulimitsOut[1], typeName, softLimit, hardLimit)
}

func verifyUlimit(t *testing.T, output *ecs.Ulimit, name string, softLimit, hardLimit int64) {
	if name != *output.Name {
		t.Errorf("Expected name [%s] But was [%s]", name, *output.Name)
	}
	if softLimit != *output.SoftLimit {
		t.Errorf("Expected softLimit [%d] But was [%d]", softLimit, *output.SoftLimit)
	}
	if hardLimit != *output.HardLimit {
		t.Errorf("Expected hardLimit [%d] But was [%d]", hardLimit, *output.HardLimit)
	}
}

func convertToTaskDefinitionInTest(t *testing.T, name string, volumeConfig *config.VolumeConfig, serviceConfig *config.ServiceConfig, taskRoleArn string, launchType string) *ecs.TaskDefinition {
	volumeConfigs := make(map[string]*config.VolumeConfig)
	if volumeConfig != nil {
		volumeConfigs[namedVolume] = volumeConfig
	}

	serviceConfigs := config.NewServiceConfigs()
	serviceConfigs.Add(name, serviceConfig)

	envLookup, err := GetDefaultEnvironmentLookup()
	if err != nil {
		t.Fatal("Unexpected error setting up environment lookup")
	}
	resourceLookup, err := GetDefaultResourceLookup()
	if err != nil {
		t.Fatal("Unexpected error setting up resource lookup")
	}
	context := &project.Context{
		ProjectName:       "ProjectName",
		Project:           &project.Project{},
		EnvironmentLookup: envLookup,
		ResourceLookup:    resourceLookup,
	}
	taskDefinition, err := ConvertToTaskDefinition(context, volumeConfigs, serviceConfigs, taskRoleArn, launchType, nil)
	if err != nil {
		t.Errorf("Expected to convert [%v] serviceConfigs without errors. But got [%v]", serviceConfig, err)
	}
	return taskDefinition
}

func serviceConfigWithDefaultNetworks() *config.ServiceConfig {
	return &config.ServiceConfig{
		Networks: &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}
}

func convertToTaskDefWithEcsParamsInTest(t *testing.T, names []string, volumeConfig *config.VolumeConfig, serviceConfig *config.ServiceConfig, taskRoleArn string, ecsParams *ECSParams) (*ecs.TaskDefinition, error) {
	volumeConfigs := make(map[string]*config.VolumeConfig)
	if volumeConfig != nil {
		volumeConfigs[namedVolume] = volumeConfig
	}

	serviceConfigs := config.NewServiceConfigs()
	for _, name := range names {
		serviceConfigs.Add(name, serviceConfig)
	}

	envLookup, err := GetDefaultEnvironmentLookup()
	if err != nil {
		t.Fatal("Unexpected error setting up environment lookup")
	}
	resourceLookup, err := GetDefaultResourceLookup()
	if err != nil {
		t.Fatal("Unexpected error setting up resource lookup")
	}
	context := &project.Context{
		ProjectName:       "ProjectName",
		Project:           &project.Project{},
		EnvironmentLookup: envLookup,
		ResourceLookup:    resourceLookup,
	}
	taskDefinition, err := ConvertToTaskDefinition(context, volumeConfigs, serviceConfigs, taskRoleArn, "", ecsParams)
	if err != nil {
		return nil, err
	}

	return taskDefinition, nil
}

func findContainerByName(name string, containerDefs []*ecs.ContainerDefinition) *ecs.ContainerDefinition {
	for _, cd := range containerDefs {
		if aws.StringValue(cd.Name) == name {
			return cd
		}
	}
	return nil
}

func TestIsZeroForEmptyConfig(t *testing.T) {
	serviceConfig := &config.ServiceConfig{}

	configValue := reflect.ValueOf(serviceConfig).Elem()
	configType := configValue.Type()

	for i := 0; i < configValue.NumField(); i++ {
		f := configValue.Field(i)
		ft := configType.Field(i)
		isZero := isZero(f)
		if !isZero {
			t.Errorf("Expected field [%s] to be zero but was not", ft.Name)
		}
	}
}

func TestIsZeroWhenConfigHasValues(t *testing.T) {
	hasValues := map[string]bool{
		"CPUShares":      true,
		"Command":        true,
		"Hostname":       true,
		"Image":          true,
		"Links":          true,
		"MemLimit":       true,
		"MemReservation": true,
		"Privileged":     true,
		"ReadOnly":       true,
		"SecurityOpt":    true,
		"User":           true,
		"WorkingDir":     true,
	}

	serviceConfig := &config.ServiceConfig{
		CPUShares:      yaml.StringorInt(int64(10)),
		Command:        []string{"cmd"},
		Hostname:       "foobarbaz",
		Image:          "testimage",
		Links:          []string{"container1"},
		MemLimit:       yaml.MemStringorInt(int64(104857600)),
		MemReservation: yaml.MemStringorInt(int64(52428800)),
		Privileged:     true,
		ReadOnly:       true,
		SecurityOpt:    []string{"label:type:test_virt"},
		User:           "user",
		WorkingDir:     "/var",
	}

	configValue := reflect.ValueOf(serviceConfig).Elem()
	configType := configValue.Type()

	for i := 0; i < configValue.NumField(); i++ {
		f := configValue.Field(i)
		ft := configType.Field(i)
		fieldName := ft.Name

		zeroValue := isZero(f)
		_, hasValue := hasValues[fieldName]
		if zeroValue == hasValue {
			t.Errorf("Expected field [%s]: hasValues[%v] but found[%t]", ft.Name, hasValues, !zeroValue)
		}
	}
}

func TestMemReservationHigherThanMemLimit(t *testing.T) {
	name := "api"
	cpu := int64(131072) // 128 * 1024
	command := "cmd"
	hostname := "local360"
	image := "testimage"
	memory := int64(65536) // 64mb
	privileged := true
	readOnly := true
	user := "user"
	workingDir := "/var"

	serviceConfig := &config.ServiceConfig{
		CPUShares:      yaml.StringorInt(cpu),
		Command:        []string{command},
		Hostname:       hostname,
		Image:          image,
		MemLimit:       yaml.MemStringorInt(int64(524288) * memory),
		MemReservation: yaml.MemStringorInt(int64(1048576) * memory),
		Privileged:     privileged,
		ReadOnly:       readOnly,
		User:           user,
		WorkingDir:     workingDir,
		Networks:       &yaml.Networks{Networks: []*yaml.Network{defaultNetwork}},
	}

	volumeConfigs := make(map[string]*config.VolumeConfig)

	serviceConfigs := config.NewServiceConfigs()
	serviceConfigs.Add(name, serviceConfig)

	envLookup, err := GetDefaultEnvironmentLookup()
	assert.NoError(t, err, "Unexpected error setting up environment lookup")
	resourceLookup, err := GetDefaultResourceLookup()
	assert.NoError(t, err, "Unexpected error setting up resource lookup")
	context := &project.Context{
		ProjectName:       "ProjectName",
		Project:           &project.Project{},
		EnvironmentLookup: envLookup,
		ResourceLookup:    resourceLookup,
	}
	_, err = ConvertToTaskDefinition(context, volumeConfigs, serviceConfigs, "", "", nil)
	assert.EqualError(t, err, "mem_limit must be greater than mem_reservation")
}

func TestSortedGoString(t *testing.T) {
	family := aws.String("family1")
	name := aws.String("foo")
	command := aws.StringSlice([]string{"dark", "side", "of", "the", "moon"})
	dockerLabels := map[string]string{
		"label1":         "",
		"com.foo.label2": "value",
	}

	inputA := ecs.RegisterTaskDefinitionInput{
		Family: family,
		ContainerDefinitions: []*ecs.ContainerDefinition{
			{
				Name:         name,
				Command:      command,
				DockerLabels: aws.StringMap(dockerLabels),
			},
		},
	}
	inputB := ecs.RegisterTaskDefinitionInput{
		ContainerDefinitions: []*ecs.ContainerDefinition{
			{
				Command:      command,
				Name:         name,
				DockerLabels: aws.StringMap(dockerLabels),
			},
		},
		Family: family,
	}

	strA, err := SortedGoString(inputA)
	assert.NoError(t, err, "Unexpected error generating sorted map string")
	strB, err := SortedGoString(inputB)
	assert.NoError(t, err, "Unexpected error generating sorted map string")

	assert.Equal(t, strA, strB, "Sorted inputs should match")
}
