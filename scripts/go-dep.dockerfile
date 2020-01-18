ARG GO_RELEASE_TAG=1.11
FROM golang:${GO_RELEASE_TAG}

ARG DEP_RELEASE_TAG=v0.4.1
RUN set -x; \
    curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh && \
    go get github.com/golang/mock/mockgen && \
    go get golang.org/x/tools/cmd/goimports && \
    mkdir -p -m 777 /usr/src/app/src/github.com/aws/amazon-ecs-cli && \
    chmod -R ugo=rwX /usr/src
