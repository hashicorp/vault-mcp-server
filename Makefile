SHELL := /usr/bin/env bash -euo pipefail -c

BINARY_NAME ?= ./bin/vault-mcp-server
BASENAME := $(shell basename $(BINARY_NAME))
VERSION ?= $(if $(shell printenv VERSION),$(shell printenv VERSION),dev)

GO=go
DOCKER=docker

DOCKER_REGISTRY ?= docker.io
IMAGE_NAME = $(DOCKER_REGISTRY)/$(BASENAME):$(VERSION)

TARGET_DIR ?= $(CURDIR)/dist

# Build flags
LDFLAGS=-ldflags="-s -w -X github.com/hashicorp/$(BASENAME)/version.GitCommit=$(shell git rev-parse HEAD) -X github.com/hashicorp/$(BASENAME)/version.BuildDate=$(shell git show --no-show-signature -s --format=%cd --date=format:"%Y-%m-%dT%H:%M:%SZ" HEAD)"

.PHONY: all build crt-build test test-e2e clean deps docker-build run-http docker-run-http test-http cleanup-test-containers help

# Default target
all: build

# Build the binary
# Get local ARCH; on Intel Mac, 'uname -m' returns x86_64 which we turn into amd64.
# Not using 'go env GOOS/GOARCH' here so 'make docker' will work without local Go install.
# Always use CGO_ENABLED=0 to ensure a statically linked binary is built
ARCH     = $(shell A=$$(uname -m); [ $$A = x86_64 ] && A=amd64; echo $$A)
OS       = $(shell uname | tr [[:upper:]] [[:lower:]])
build:
	CGO_ENABLED=0 GOARCH=$(ARCH) GOOS=$(OS) $(GO) build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/$(BASENAME)

crt-build:
	@mkdir -p $(TARGET_DIR)
	@$(CURDIR)/scripts/crt-build.sh build
	@cp $(CURDIR)/LICENSE $(TARGET_DIR)/LICENSE.txt

# Run tests
test:
	$(GO) test -v ./...

# Run e2e tests
test-e2e:
	@trap '$(MAKE) cleanup-test-containers' EXIT; $(GO) test -v --tags e2e ./e2e

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	$(GO) clean

# Download dependencies
deps:
	$(GO) mod download

# Build docker image
docker-build:
	$(DOCKER) build --build-arg VERSION=$(VERSION) -t $(IMAGE_NAME) .

docker-push: docker-build
	$(DOCKER) push $(IMAGE_NAME)

# Run HTTP server locally
run-http:
	./$(BINARY_NAME) http --transport-port 8080

# Run HTTP server in Docker
docker-run-http:
	$(DOCKER) run -p 8080:8080 --rm $(IMAGE_NAME) ./$(BASENAME) http --transport-port 8080

# Test HTTP endpoint
test-http:
	@echo "Testing StreamableHTTP server health endpoint..."
	@curl -f http://localhost:8080/health || echo "Health check failed - make sure server is running with 'make run-http'"
	@echo "StreamableHTTP MCP endpoint available at: http://localhost:8080/mcp"

# Run docker container
# docker-run:
# 	$(DOCKER) run -it --rm $(BINARY_NAME):$(VERSION)

# Clean up test containers
cleanup-test-containers:
	@echo "Cleaning up test containers..."
	@$(DOCKER) ps -q --filter "ancestor=$(BASENAME):test-e2e" | xargs -r $(DOCKER) stop
	@$(DOCKER) ps -aq --filter "ancestor=$(BASENAME):test-e2e" | xargs -r $(DOCKER) rm
	@echo "Test container cleanup complete"

# Show help
help:
	@echo "Available targets:"
	@echo "  all            - Build the binary (default)"
	@echo "  build          - Build the binary"
	@echo "  test           - Run all tests"
	@echo "  test-e2e       - Run end-to-end tests"
	@echo "  clean          - Remove build artifacts"
	@echo "  deps           - Download dependencies"
	@echo "  docker-build   - Build docker image"
	@echo "  run-http       - Run StreamableHTTP server locally on port 8080"
	@echo "  docker-run-http - Run StreamableHTTP server in Docker on port 8080"
	@echo "  test-http      - Test StreamableHTTP health endpoint"
	@echo "  cleanup-test-containers - Stop and remove all test containers"
	@echo "  help           - Show this help message"
