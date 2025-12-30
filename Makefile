.PHONY: all build run run-mock clean

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

clean:
	rm -rf bin out
