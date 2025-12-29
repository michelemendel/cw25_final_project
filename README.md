# Cyberwise 25 Final Project: Passive Reconnaissance Pipeline

A Go-based workflow orchestrating industry-standard recon tools (Subfinder → httpx → nuclei) to discover subdomains, identify live web assets, and detect vulnerabilities across multiple domains in parallel.

## Overview

This project implements an automated passive reconnaissance pipeline using [go-workflows](https://github.com/cschleiden/go-workflows). It is designed to:

- **Parallelize domain processing**: Efficiently handle multiple domains concurrently.
- **Configurable scanning**: customizable via `config.yaml`.
- **Structured Reporting**: Generates Markdown reports and JSONL data for findings.
- **Resilience**: Includes retry logic for transient errors.

## Documentation

- [Project Specification](docs/spec.md): Detailed project requirements and architecture.
- [Test Sites](docs/test_sites.md): List of sites used for testing.

## Prerequisites

- Go 1.25+
- [Subfinder](https://github.com/projectdiscovery/subfinder) installed and in your PATH.
- [httpx](https://github.com/projectdiscovery/httpx) installed and in your PATH.
- [nuclei](https://github.com/projectdiscovery/nuclei) installed and in your PATH.

## Installation

Clone the repository:

```bash
git clone https://github.com/michelemendel/cw25_final_project.git
cd cw25_final_project
```

### Installing Required Tools

**For macOS:** Install the required reconnaissance tools using Homebrew:

```bash
brew install subfinder
brew install httpx
brew install nuclei
```

Note: These installation instructions are for macOS. For other operating systems, please refer to the official installation guides for each tool:

- [Subfinder Installation](https://github.com/projectdiscovery/subfinder#installation)
- [httpx Installation](https://github.com/projectdiscovery/httpx#installation)
- [nuclei Installation](https://github.com/projectdiscovery/nuclei#installation)

## Usage

### Configuration

Edit `config.yaml` to configure scanner settings, timeout, and output directory.
Edit `domains.txt` to add the list of root domains to scan.

### Build and Run

To build the project:

```bash
make build
```

This will create the executable at `bin/recon-pipeline`.

To run the pipeline:

```bash
make run
```

Or directly:

```bash
./bin/recon-pipeline
```

### Output

Results are saved in the `out/` directory (or as configured in `config.yaml`), organized by domain.

- `scope.json`
- `subdomains.jsonl`
- `live_hosts.jsonl`
- `nuclei_findings.jsonl`
- `report.md`

Global summary: `out/report-summary.md`

## Development

Run tests:

```bash
make test
```

Clean build artifacts:

```bash
make clean
```
