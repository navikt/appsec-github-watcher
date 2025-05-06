.PHONY: all build clean run test fmt tidy docker check vet help

# Default target
all: tidy fmt vet test build

# Build the application
build:
	go build -o bin/appsec-github-watcher cmd/appsec-github-watcher/*.go

# Run the application
run:
	go run cmd/appsec-github-watcher/main.go

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

# Build Docker image
docker:
	docker build -t appsec-github-watcher .

# Check for code quality issues
check: fmt vet lint test

# Run go vet
vet:
	go vet ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  all       - Run tidy, fmt, vet, test, and build"
	@echo "  build     - Build the application"
	@echo "  clean     - Remove build artifacts"
	@echo "  run       - Run the application locally"
	@echo "  test      - Run all tests"
	@echo "  fmt       - Format code with go fmt"
	@echo "  tidy      - Ensure dependencies are up to date"
	@echo "  docker    - Build Docker image"
	@echo "  check     - Run all code quality checks and tests"
	@echo "  vet       - Run go vet for static analysis"
	@echo "  lint      - Run golangci-lint for advanced linting"
	@echo "  help      - Show this help message"

