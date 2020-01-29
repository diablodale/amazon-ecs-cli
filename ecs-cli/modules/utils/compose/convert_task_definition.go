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

	"github.com/aws/amazon-ecs-cli/ecs-cli/modules/cli/compose/adapter"
	"github.com/aws/amazon-ecs-cli/ecs-cli/modules/utils/regcredio"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
	"github.com/docker/cli/cli/compose/types"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// TaskDefParams contains basic fields to build an ECS task definition
type TaskDefParams struct {
	networkMode      string
	taskRoleArn      string
	cpu              string
	memory           string
	pidMode          string
	ipcMode          string
	containerDefs    ContainerDefs
	executionRoleArn string
}

// ConvertTaskDefParams contains the inputs required to convert compose & ECS inputs into an ECS task definition
type ConvertTaskDefParams struct {
	TaskDefName            string
	TaskRoleArn            string
	RequiredCompatibilites string
	Volumes                *adapter.Volumes
	ContainerConfigs       []adapter.ContainerConfig
	ECSParams              *ECSParams
	ECSRegistryCreds       *regcredio.ECSRegistryCredsOutput
}

// ConvertToTaskDefinition transforms the yaml configs to its ecs equivalent (task definition)
func ConvertToTaskDefinition(params ConvertTaskDefParams) (*ecs.TaskDefinition, error) {
	if len(params.ContainerConfigs) == 0 {
		return nil, errors.New("cannot create a task definition with no containers; invalid service config")
	}

	// Instantiates zero values for fields on task def specified by ecs-params
	taskDefParams, err := convertTaskDefParams(params.ECSParams)
	if err != nil {
		return nil, err
	}

	// The task-role-arn flag takes precedence over a taskRoleArn value specified in ecs-params file.
	if params.TaskRoleArn == "" {
		params.TaskRoleArn = taskDefParams.taskRoleArn
	}

	// Create containerDefinitions
	containerDefinitions := []*ecs.ContainerDefinition{}

	for _, containerConfig := range params.ContainerConfigs {
		name := containerConfig.Name
		// Check if there are ecs-params specified for the container
		ecsContainerDef := &ContainerDef{Essential: true}
		if cd, ok := taskDefParams.containerDefs[name]; ok {
			ecsContainerDef = &cd
		}

		// Validate essential containers
		count := len(params.ContainerConfigs)
		if !hasEssential(taskDefParams.containerDefs, count) {
			return nil, errors.New("Task definition does not have any essential containers")
		}

		taskVals := taskLevelValues{
			MemLimit: taskDefParams.memory,
		}

		containerDef, err := reconcileContainerDef(&containerConfig, ecsContainerDef, taskVals)
		if err != nil {
			return nil, err
		}

		containerDefinitions = append(containerDefinitions, containerDef)
	}

	ecsVolumes, err := convertToECSVolumes(params.Volumes, params.ECSParams)
	if err != nil {
		return nil, err
	}

	executionRoleArn := taskDefParams.executionRoleArn

	placementConstraints := convertToTaskDefinitionConstraints(params.ECSParams)

	// Check for and apply provided ecs-registry-creds values
	if params.ECSRegistryCreds != nil {
		err := addRegistryCredsToContainerDefs(containerDefinitions, params.ECSRegistryCreds.CredentialResources.ContainerCredentials)
		if err != nil {
			return nil, err
		}

		// if provided, add or replace existing executionRoleArn with value from cred file
		if params.ECSRegistryCreds.CredentialResources.TaskExecutionRole != "" {
			newExecutionRole := params.ECSRegistryCreds.CredentialResources.TaskExecutionRole

			if executionRoleArn != "" {
				// TODO: refactor 'showResourceOverrideMsg()' to take in override src and use here
				log.WithFields(log.Fields{
					"option name": "task_execution_role",
				}).Infof("Using "+regcredio.ECSCredFileBaseName+" value as override (was %s but is now %s)", executionRoleArn, newExecutionRole)
			} else {
				log.WithFields(log.Fields{
					"option name": "task_execution_role",
				}).Infof("Using "+regcredio.ECSCredFileBaseName+" value %s", newExecutionRole)
			}
			executionRoleArn = newExecutionRole
		}
	}

	// Note: this is later converted into an ecs.RegisterTaskDefinitionInput in entity_helper.go
	taskDefinition := &ecs.TaskDefinition{
		Family:               aws.String(params.TaskDefName),
		ContainerDefinitions: containerDefinitions,
		Volumes:              ecsVolumes,
		TaskRoleArn:          aws.String(params.TaskRoleArn),
		NetworkMode:          aws.String(taskDefParams.networkMode),
		Cpu:                  aws.String(taskDefParams.cpu),
		Memory:               aws.String(taskDefParams.memory),
		ExecutionRoleArn:     aws.String(executionRoleArn),
		PlacementConstraints: placementConstraints,
	}

	// Set launch type
	if params.RequiredCompatibilites != "" {
		taskDefinition.RequiresCompatibilities = []*string{aws.String(params.RequiredCompatibilites)}
	}
	if taskDefParams.pidMode != "" {
		taskDefinition.SetPidMode(taskDefParams.pidMode)
	}
	if taskDefParams.ipcMode != "" {
		taskDefinition.SetIpcMode(taskDefParams.ipcMode)
	}
	return taskDefinition, nil
}

func resolveHealthCheck(serviceName string, healthCheck *ecs.HealthCheck, ecsParamsHealthCheck *HealthCheck) (*ecs.HealthCheck, error) {
	if ecsParamsHealthCheck != nil {
		healthCheckOverride, err := ecsParamsHealthCheck.ConvertToECSHealthCheck()
		if err != nil {
			return nil, err
		}

		if healthCheck != nil {
			healthCheck.Command = resolveStringSliceResourceOverride(serviceName, healthCheck.Command, healthCheckOverride.Command, "healthcheck command")
			healthCheck.Interval = resolveIntPointerResourceOverride(serviceName, healthCheck.Interval, healthCheckOverride.Interval, "healthcheck interval")
			healthCheck.Retries = resolveIntPointerResourceOverride(serviceName, healthCheck.Retries, healthCheckOverride.Retries, "healthcheck retries")
			healthCheck.Timeout = resolveIntPointerResourceOverride(serviceName, healthCheck.Timeout, healthCheckOverride.Timeout, "healthcheck timeout")
			healthCheck.StartPeriod = resolveIntPointerResourceOverride(serviceName, healthCheck.StartPeriod, healthCheckOverride.StartPeriod, "healthcheck start_period")
		} else {
			healthCheck = healthCheckOverride
		}
	}
	// validate healthcheck
	if healthCheck != nil && healthCheck.Validate() != nil {
		return healthCheck, fmt.Errorf("%s: test/command is a required field for container healthcheck", serviceName)
	}
	return healthCheck, nil
}

func resolveIntResourceOverride(serviceName string, composeVal, ecsParamsVal int64, option string) int64 {
	if composeVal > 0 && ecsParamsVal > 0 {
		showResourceOverrideMsg(serviceName, composeVal, ecsParamsVal, option)
	}
	if ecsParamsVal > 0 {
		return ecsParamsVal
	}
	return composeVal
}

func resolveIntPointerResourceOverride(serviceName string, composeVal, ecsParamsVal *int64, option string) *int64 {
	if composeVal != nil && ecsParamsVal != nil {
		showResourceOverrideMsg(serviceName, aws.Int64Value(composeVal), aws.Int64Value(ecsParamsVal), option)
	}
	if ecsParamsVal != nil {
		return ecsParamsVal
	}
	return composeVal
}

func resolveStringSliceResourceOverride(serviceName string, composeVal, ecsParamsVal []*string, option string) []*string {
	if len(composeVal) > 0 && len(ecsParamsVal) > 0 {
		log.WithFields(log.Fields{
			"option name":  option,
			"service name": serviceName,
		}).Infof("Using ecs-params value as override")
	}
	if len(ecsParamsVal) > 0 {
		return ecsParamsVal
	}
	return composeVal
}

func showResourceOverrideMsg(serviceName string, val int64, override int64, option string) {
	overrideMsg := "Using ecs-params value as override (was %v but is now %v)"

	log.WithFields(log.Fields{
		"option name":  option,
		"service name": serviceName,
	}).Infof(overrideMsg, val, override)
}

// convertToECSVolumes transforms the map of hostPaths to the format of ecs.Volume
func convertToECSVolumes(hostPaths *adapter.Volumes, ecsParams *ECSParams) ([]*ecs.Volume, error) {
	output := []*ecs.Volume{}
	// volumes with a host path
	for hostPath, volName := range hostPaths.VolumeWithHost {
		ecsVolume := &ecs.Volume{
			Name: aws.String(volName),
			Host: &ecs.HostVolumeProperties{
				SourcePath: aws.String(hostPath),
			}}
		output = append(output, ecsVolume)
	}

	// volumes without host path (allowed to have Docker Volume Configuration)
	volumesWithoutHost, err := mergeVolumesWithoutHost(hostPaths.VolumeEmptyHost, ecsParams)
	if err != nil {
		return nil, err
	}
	output = append(output, volumesWithoutHost...)

	// volumes with driver declaration and no provisioning/creating
	volumesWithDriverNoProvision, err := mergeVolumesWithDriverNoProvision(hostPaths.VolumeWithDriverNoProvision, ecsParams)
	if err != nil {
		return nil, err
	}
	output = append(output, volumesWithDriverNoProvision...)

	// volumes with provisioning/creating
	volumesWithConfigProvision, err := mergeVolumesWithConfigProvision(hostPaths.VolumeWithConfigProvision, ecsParams)
	if err != nil {
		return nil, err
	}
	output = append(output, volumesWithConfigProvision...)

	return output, nil
}

func convertToECSFirelensConfiguration(firelensConfiguration FirelensConfiguration) *ecs.FirelensConfiguration {
	ecsFirelensConfiguration := &ecs.FirelensConfiguration{
		Type:    aws.String(firelensConfiguration.Type),
		Options: aws.StringMap(firelensConfiguration.Options),
	}
	return ecsFirelensConfiguration
}

func convertToECSSecrets(secrets []Secret) []*ecs.Secret {
	var ecsSecrets []*ecs.Secret
	for _, secret := range secrets {
		s := &ecs.Secret{
			ValueFrom: aws.String(secret.ValueFrom),
			Name:      aws.String(secret.Name),
		}
		ecsSecrets = append(ecsSecrets, s)
	}
	return ecsSecrets
}

func mergeHelperDockerVolsToEcsVols(dockerVolumes map[string]DockerVolume) []*ecs.Volume {
	output := []*ecs.Volume{}

	for volName, dVol := range dockerVolumes {
		ecsVolume := &ecs.Volume{
			Name: aws.String(volName),
		}
		if dVol.Name != "" {
			ecsVolume.DockerVolumeConfiguration = &ecs.DockerVolumeConfiguration{
				Autoprovision: dVol.Autoprovision,
			}
			if dVol.Driver != nil {
				ecsVolume.DockerVolumeConfiguration.Driver = dVol.Driver
			}
			if dVol.Scope != nil {
				ecsVolume.DockerVolumeConfiguration.Scope = dVol.Scope
			}
			if dVol.DriverOptions != nil {
				ecsVolume.DockerVolumeConfiguration.DriverOpts = aws.StringMap(dVol.DriverOptions)
			}
			if dVol.Labels != nil {
				ecsVolume.DockerVolumeConfiguration.Labels = aws.StringMap(dVol.Labels)
			}
		}
		output = append(output, ecsVolume)
	}
	return output
}

func mergeVolumesWithoutHost(composeVolumes []string, ecsParams *ECSParams) ([]*ecs.Volume, error) {
	volumesWithoutHost := make(map[string]DockerVolume)

	for _, volName := range composeVolumes {
		volumesWithoutHost[volName] = DockerVolume{}
	}

	if ecsParams != nil {
		for _, dockerVol := range ecsParams.TaskDefinition.DockerVolumes {
			if dockerVol.Name != "" {
				volumesWithoutHost[dockerVol.Name] = dockerVol
			} else {
				return nil, fmt.Errorf("Name is required when specifying a docker volume")
			}
		}
	}
	return mergeHelperDockerVolsToEcsVols(volumesWithoutHost), nil
}

func mergeVolumesWithDriverNoProvision(composeVolumes map[string]string, ecsParams *ECSParams) ([]*ecs.Volume, error) {
	volumesWithDriverNoProvision := make(map[string]DockerVolume)

	for volName, volDriver := range composeVolumes {
		volumesWithDriverNoProvision[volName] = DockerVolume{
			Name:		   volName,
			Autoprovision: aws.Bool(false),
			Scope:         aws.String("shared"),
			Driver:        aws.String(volDriver),
		}
	}

	if ecsParams != nil {
		for _, dockerVol := range ecsParams.TaskDefinition.DockerVolumes {
			if dockerVol.Name != "" {
				if _, foundKey := volumesWithDriverNoProvision[dockerVol.Name]; foundKey {
					return nil, fmt.Errorf("External volume %s in docker-compose appears also in ecs-params file", dockerVol.Name)
				}
			} else {
				return nil, fmt.Errorf("Name is required when specifying a docker volume")
			}
		}
	}
	return mergeHelperDockerVolsToEcsVols(volumesWithDriverNoProvision), nil
}

func mergeVolumesWithConfigProvision(composeVolumes map[string]types.VolumeConfig, ecsParams *ECSParams) ([]*ecs.Volume, error) {
	volumesWithConfigProvision := make(map[string]DockerVolume)

	for volName, volConfig := range composeVolumes {
		volumesWithConfigProvision[volName] = DockerVolume{
			Name:		   volName,
			Scope:         aws.String("task"),
			Autoprovision: nil,
			Driver:        aws.String(volConfig.Driver),
			DriverOptions: volConfig.DriverOpts,
			Labels:        volConfig.Labels,
		}
	}

	if ecsParams != nil {
		for _, dockerVol := range ecsParams.TaskDefinition.DockerVolumes {
			if dockerVol.Name != "" {
				if _, foundKey := volumesWithConfigProvision[dockerVol.Name]; foundKey {
					return nil, fmt.Errorf("Volume %s with configuration in docker-compose appears also in ecs-params file", dockerVol.Name)
				}
			} else {
				return nil, fmt.Errorf("Name is required when specifying a docker volume")
			}
		}
	}
	return mergeHelperDockerVolsToEcsVols(volumesWithConfigProvision), nil
}

func hasEssential(ecsParamsContainerDefs ContainerDefs, count int) bool {
	// If the customer does not set the "essential" field on any container
	// definition, ECS will mark all containers in a TaskDefinition as
	// essential. Previously, since the customer could not pass in the
	// essential field, Task Definitions created through the CLI marked all
	// containers as essential.

	// Now that the essential field can  be set by the customer via the
	// the ecs-params.yml file, we want to make sure that there is still at
	// least one essential container, i.e. that the customer does not
	// explicitly set all containers to be non-essential.

	nonEssentialCount := 0

	for _, containerDef := range ecsParamsContainerDefs {
		if !containerDef.Essential {
			nonEssentialCount++
		}
	}

	// 'count' is the total number of containers specified in the service config
	return nonEssentialCount != count
}

// Converts fields from ecsParams into the appropriate types for fields on an
// ECS Task Definition
func convertTaskDefParams(ecsParams *ECSParams) (params TaskDefParams, e error) {
	if ecsParams == nil {
		return params, nil
	}

	taskDef := ecsParams.TaskDefinition
	params.networkMode = taskDef.NetworkMode
	params.taskRoleArn = taskDef.TaskRoleArn
	params.containerDefs = taskDef.ContainerDefinitions
	params.cpu = taskDef.TaskSize.Cpu
	params.memory = taskDef.TaskSize.Memory
	params.executionRoleArn = taskDef.ExecutionRole
	params.ipcMode = taskDef.IPCMode
	params.pidMode = taskDef.PIDMode

	return params, nil
}

func addRegistryCredsToContainerDefs(containerDefs []*ecs.ContainerDefinition, containerCreds map[string]regcredio.CredsOutputEntry) error {
	credsMap, err := getContainersToCredsMap(containerCreds)
	if err != nil {
		return err
	}
	// set registry creds to applicable container definitions
	if len(credsMap) > 0 {
		for _, containerDef := range containerDefs {
			containerName := aws.StringValue(containerDef.Name)

			if foundCredParam := credsMap[containerName]; foundCredParam != "" {
				if containerDef.RepositoryCredentials != nil && aws.StringValue(containerDef.RepositoryCredentials.CredentialsParameter) != "" {
					log.WithFields(log.Fields{
						"container name": containerName,
						"option name":    "credentials_parameter",
					}).Infof("Using "+regcredio.ECSCredFileBaseName+" value as override (was %s but is now %s)", *containerDef.RepositoryCredentials.CredentialsParameter, foundCredParam)
				} else {
					log.WithFields(log.Fields{
						"container name": containerName,
						"option name":    "credentials_parameter",
					}).Infof("Using "+regcredio.ECSCredFileBaseName+" value %s", foundCredParam)
				}
				// set RepositoryCredentials to new value
				containerRepoCreds := ecs.RepositoryCredentials{
					CredentialsParameter: aws.String(foundCredParam),
				}
				containerDef.RepositoryCredentials = &containerRepoCreds

				// remove container entry from cred map
				delete(credsMap, containerName)
			}
		}
		// if credMap contains container names not present in our container definitions, log a warning
		if len(credsMap) > 0 {
			unusedContainers := make([]string, 0, len(credsMap))
			for container := range credsMap {
				unusedContainers = append(unusedContainers, container)
			}
			log.Warnf("Containers listed with registry credentials but not used: %v", unusedContainers)
		}
	}
	return nil
}

func getContainersToCredsMap(containerCreds map[string]regcredio.CredsOutputEntry) (map[string]string, error) {
	containerToCredMap := make(map[string]string)

	for registry, credEntry := range containerCreds {
		if credEntry.CredentialARN != "" && len(credEntry.ContainerNames) > 0 {
			credParam := credEntry.CredentialARN

			for _, containerName := range credEntry.ContainerNames {
				// if duplicate entries for a given container are found, return error
				if containerToCredMap[containerName] != "" {
					return nil, fmt.Errorf("Duplicate credential_parameter values found for container %s (%s and %s)", containerName, containerToCredMap[containerName], credParam)
				}

				containerToCredMap[containerName] = credParam
			}
		} else {
			log.Warnf("No containers found for registry %s", registry)
		}
	}
	return containerToCredMap, nil
}

func convertToTaskDefinitionConstraints(ecsParams *ECSParams) []*ecs.TaskDefinitionPlacementConstraint {
	if ecsParams == nil {
		return nil
	}

	placementConstraints := ecsParams.TaskDefinition.PlacementConstraints
	if len(placementConstraints) > 0 {
		tdPcs := make([]*ecs.TaskDefinitionPlacementConstraint, len(placementConstraints))
		for i, pc := range placementConstraints {
			tdPcs[i] = &ecs.TaskDefinitionPlacementConstraint{
				Type:       aws.String(pc.Type),
				Expression: aws.String(pc.Expression),
			}
		}
		return tdPcs
	}

	return nil
}
