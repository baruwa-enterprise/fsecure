.PHONY: build clean test help default

BIN_NAME=fsecurescan

VERSION := $(shell grep "const Version " cmd/fsecurescan/version.go | sed -E 's/.*"(.+)"$$/\1/')
GIT_COMMIT=$(shell git rev-parse HEAD)
GIT_DIRTY=$(shell test -n "`git status --porcelain`" && echo "+CHANGES" || true)
IMAGE_NAME := "baruwa/fsecurescan"

default: test

help:
	@echo 'Management commands for fsecure:'
	@echo
	@echo 'Usage:'
	@echo '    make build           Compile the project.'
	
	@echo '    make clean           Clean the directory tree.'
	@echo

build:
	@echo "building ${BIN_NAME} ${VERSION}"
	@echo "GOPATH=${GOPATH}"
	go build -ldflags "-X main.GitCommit=${GIT_COMMIT}${GIT_DIRTY} -X main.VersionPrerelease=DEV" -o bin/${BIN_NAME} ./cmd/fsecurescan

clean:
	@test ! -e bin/${BIN_NAME} || rm bin/${BIN_NAME}

test:
	go test -coverprofile cp.out ./...

test-coverage:
	go tool cover -html=cp.out

