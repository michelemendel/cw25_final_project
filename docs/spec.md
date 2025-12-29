# Cyberwise 25 Final Project Specification

## Project Description

Automated Passive Reconnaissance Pipeline

A Go-based workflow orchestrating industry-standard recon tools (Subfinder → httpx → nuclei)
to discover subdomains, identify live web assets, and detect vulnerabilities across multiple
domains in parallel. Demonstrates task orchestration with go-workflows, configurable
scanning, retry logic, and structured reporting for bug bounty / pentest workflows.

## Project Requirements

- Parallelize domains
- Configurable template sets via `config.yaml`
- Retry logic per task for transient CLI errors
- JSONL data flow between stages

## Main Tools

- **Programming language**: Golang (concurrent programming, CLI integration)
- **Task orchestration**: go-workflows
  - One workflow run per domain
  - Activities: `ParseScope` → `RunSubfinder` → `RunHttpx` → `RunNuclei` → `GenerateReport`
  - Activity retries + backoff for transient errors
  - Multiple workers for domain parallelism

## Tasks and Tools for Passive Recon

### 1. Scope configuration & input normalization

- **Tool**: Go stdlib (`os`, `bufio`, `encoding/json`, `flag`/`cobra`)
- **Input**:
  - `domains.txt` (one root domain per line)
  - `config.yaml`:

```yaml
nuclei_templates: ['http/misconfiguration/', 'http/exposed-panels/']
nuclei_tags: ['cve', 'exposure']
concurrency: 50
timeout: 10s
output_dir: 'out'
```

- **Output**: `out/<domain>/scope.json`:

```yaml
[{ 'domain': 'example.com', 'timestamp': '2025-12-29T12:00:00Z' }]
```

### 2. Subdomain Enumeration

- **Tool**: Subfinder CLI (`subfinder -json`)
- **Input**: `out/<domain>/scope.json`
- **Output**: `out/<domain>/subdomains.jsonl`

### 3. Web liveness & fingerprinting

- **Tool**: httpx (`cat subdomains.jsonl | jq -r '.name' | httpx -json`)
- **Input**: `out/<domain>/subdomains.jsonl`
- **Output**: `out/<domain>/live_hosts.jsonl` (URL, status, title, tech, IP, ASN)

### 4. Template-based vulnerability scanning

- **Tool**: nuclei (`nuclei -list live_hosts.txt -t templates/ -tags misconfig -jsonl`)
- **Input**:
- `out/<domain>/live_hosts.jsonl` (extract URLs)
- Template set from `config.yaml`
- **Output**: `out/<domain>/nuclei_findings.jsonl`

### 5. Aggregation & reporting

- **Tool**: Go code + `text/template` or `github.com/nao1215/markdown`
- **Input**: All JSONL files from domain directory
  - scope.json
  - subdomains.jsonl
  - live_hosts.jsonl
  - nuclei_findings.jsonl
- **Output**:
- `out/<domain>/report.md`
- `out/report-summary.md` (global stats across domains)
  Domain: example.com
  Subdomains: 1,234 found | 45 live (3.6%)
  Findings: 3 (1 High, 2 Medium)

## Optional: Active Recon Branch

### Port Scan

- **Tools**: masscan
- **Input**: IPs from `live_hosts.jsonl`
- **Output**: `out/<domain>/masscan.json` (parsed into report)

## Directory Structure

    recon-pipeline/
    ├── main.go # go-workflows entrypoint
    ├── config.yaml # Pipeline config
    ├── domains.txt # User input
    ├── out/
    │ ├── acme.com/
    │ │ ├── scope.json
    │ │ ├── subdomains.jsonl
    │ │ ├── live_hosts.jsonl
    │ │ ├── nuclei_findings.jsonl
    │ │ └── report.md
    │ └── report-summary.md
    └── go.mod

## Success Criteria

- ✅ Parallel domain processing via go-workflows
- ✅ Configurable nuclei templates/tags
- ✅ Clean JSONL data flow (no TXT files)
- ✅ Per-task retry logic
- ✅ Professional Markdown reports with stats/tables
- ✅ Extensible (masscan branch ready)
