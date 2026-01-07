.PHONY: all build run run-mock clean build-windows build-macos build-macos-amd64 build-macos-arm64 build-all

all: build

build:
	@mkdir -p bin
	go build -o bin/recon-pipeline ./cmd/recon-pipeline

run:
	./bin/recon-pipeline

build-run: build
	./bin/recon-pipeline

run-mock: build
	@echo "Running with mock tools (mock_tools will be used instead of real tools)"
	PATH="$(shell pwd)/mock_tools:$$PATH" ./bin/recon-pipeline

# Cross-compilation targets
build-windows:
	@mkdir -p bin
	@echo "Building for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 go build -o bin/recon-pipeline-windows.exe ./cmd/recon-pipeline

build-macos-amd64:
	@mkdir -p bin
	@echo "Building for macOS (Intel/amd64)..."
	GOOS=darwin GOARCH=amd64 go build -o bin/recon-pipeline-macos-amd64 ./cmd/recon-pipeline

build-macos-arm64:
	@mkdir -p bin
	@echo "Building for macOS (Apple Silicon/arm64)..."
	GOOS=darwin GOARCH=arm64 go build -o bin/recon-pipeline-macos-arm64 ./cmd/recon-pipeline

build-macos: build-macos-amd64 build-macos-arm64
	@echo "Built macOS binaries for both architectures"

build-all: build-windows build-macos
	@echo "Built binaries for all platforms"

clean:
	rm -rf bin out
