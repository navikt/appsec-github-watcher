.PHONY: all build build-watcher build-updater clean run run-watcher run-updater test fmt tidy docker docker-watcher docker-updater check vet help

# Default target
all: tidy fmt vet test build

# Build both applications
build: build-watcher build-updater

# Build the watcher application
build-watcher:
	go build -o bin/appsec-github-watcher cmd/appsec-github-watcher/*.go

# Build the updater application
build-updater:
	go build -o bin/appsec-slack-updater cmd/appsec-slack-updater/*.go

# Run the watcher application (default for backward compatibility)
run: run-watcher

# Run the watcher application
run-watcher:
	go run cmd/appsec-github-watcher/main.go

# Run the updater application
run-updater:
	go run cmd/appsec-slack-updater/main.go

# Clean build artifacts
clean:
	rm -rf bin/*

# Run tests
test:
	go test ./... -v

# Format code
fmt:
	go fmt ./...

# Ensure dependencies are up to date
tidy:
	go mod tidy

# Build Docker image for both applications
docker: docker-watcher docker-updater

# Build Docker image for watcher
docker-watcher:
	docker build -t appsec-github-watcher --build-arg APP_NAME=appsec-github-watcher .

# Build Docker image for updater
docker-updater:
	docker build -t appsec-slack-updater --build-arg APP_NAME=appsec-slack-updater .

# Check for code quality issues
check: fmt vet test

# Run go vet
vet:
	go vet ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  all             - Run tidy, fmt, vet, test, and build"
	@echo "  build           - Build both applications"
	@echo "  build-watcher   - Build only the watcher application"
	@echo "  build-updater   - Build only the updater application"
	@echo "  clean           - Remove build artifacts"
	@echo "  run             - Run the watcher application (alias for run-watcher)"
	@echo "  run-watcher     - Run the watcher application locally"
	@echo "  run-updater     - Run the updater application locally"
	@echo "  test            - Run all tests"
	@echo "  fmt             - Format code with go fmt"
	@echo "  tidy            - Ensure dependencies are up to date"
	@echo "  docker          - Build Docker images for both applications"
	@echo "  docker-watcher  - Build Docker image for the watcher application"
	@echo "  docker-updater  - Build Docker image for the updater application"
	@echo "  check           - Run all code quality checks and tests"
	@echo "  vet             - Run go vet for static analysis"
	@echo "  help            - Show this help message"

