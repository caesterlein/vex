.PHONY: build test lint install clean release

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X github.com/caesterlein/vex/internal/cli.Version=$(VERSION)"

# Default target
all: build

# Build the binary
build:
	go build $(LDFLAGS) -o bin/vex ./cmd/vex

# Run tests
test:
	go test -v -race -cover ./...

# Run tests with coverage report
coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run linter
lint:
	golangci-lint run ./...

# Format code
fmt:
	go fmt ./...
	goimports -w .

# Install to GOPATH/bin
install:
	go install $(LDFLAGS) ./cmd/vex

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Download dependencies
deps:
	go mod download
	go mod tidy

# Run the scanner on itself
dogfood: build
	./bin/vex .

# Generate release binaries (requires goreleaser)
release:
	goreleaser release --snapshot --clean

# Check for vulnerabilities in dependencies
vuln:
	govulncheck ./...

# Development: run with live reload (requires air)
dev:
	air -c .air.toml

# Help
help:
	@echo "Available targets:"
	@echo "  build     - Build the binary"
	@echo "  test      - Run tests"
	@echo "  coverage  - Run tests with coverage report"
	@echo "  lint      - Run linter"
	@echo "  fmt       - Format code"
	@echo "  install   - Install to GOPATH/bin"
	@echo "  clean     - Clean build artifacts"
	@echo "  deps      - Download and tidy dependencies"
	@echo "  dogfood   - Run vex on itself"
	@echo "  release   - Build release binaries"
	@echo "  vuln      - Check for vulnerabilities"
