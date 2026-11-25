# raksa-netguard

[![CI](https://github.com/luminariadev/raksa-netguard/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa-netguard/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`raksa-netguard` is a lightweight, strictly defensive Go CLI for auditing local host listening sockets against a declarative security baseline and detecting reconnaissance patterns in firewall or flow logs. It is Layer 1 (Network Defense) of the **Raksa** modular Blue Team and DevSecOps suite.

## Overview

Servers routinely drift from their intended network surface: a database binds to `0.0.0.0`, a legacy daemon opens an unapproved port, or external scanners sweep edge firewalls. `raksa-netguard` addresses both surfaces without background agents or active network probing:

1. **Host Open-Port Baseline Auditing (`init`, `audit`, `policy-check`)**: Generates starter baselines from local sockets (`/proc/net/*` on Linux, `netstat -ano` on Windows), enriches findings with owning process names and PIDs, and validates drift against version-controlled YAML policies.
2. **Firewall & Flow Log Scan Detection (`analyze`, `watch`)**: Streams UFW, iptables, nftables, Windows Defender Firewall (`pfirewall.log`), or JSONL records through an O(1) amortized sliding-window tracker to detect vertical scans, horizontal sweeps, bursts, and distributed multi-source scans.
3. **CI/CD, SIEM & Agent Integration (`rules`, `mcp`)**: Emits tables, **Raksa Finding Schema v1** JSON, or **SARIF 2.1.0**, enforces `--fail-on <severity>` exit codes, and includes a built-in `stdio` JSON-RPC MCP server (`raksa-netguard mcp`) for autonomous coding and security agents.

## Hardening & Scope Boundaries

`raksa-netguard` is engineered to handle untrusted inputs safely while remaining transparent about its operational boundary:

- **Bounded-Memory Flood Protection**: Sliding-window state caps tracked source IPs (`MaxTrackedSources`, default `10,000`) and per-source buffers (`MaxEventsPerSource`, default `1,000`), evicting stale or oldest windows so spoofed-IP log floods cannot trigger unbounded memory growth.
- **IPv4 / IPv6 Canonicalization**: Normalizes IPv4-mapped IPv6 addresses (`::ffff:198.51.100.42`) and expanded wildcard notations (`0:0:0:0:0:0:0:0`, `::ffff:0.0.0.0`) so split-notation traffic cannot evade thresholds or bind checks.
- **Parser & Output Safety**: Enforces a 1 MiB YAML baseline limit, rejects unknown policy fields, strips ANSI escape sequences and control characters from terminal table rendering, and restricts webhook sinks to `http`/`https` endpoints.
- **Explicit Scope Boundary**: `raksa-netguard` is a passive host auditor and log-telemetry analyzer. It does not perform inline packet filtering (`nftables`/`ufw`), volumetric DDoS mitigation, or deep packet inspection.

## Architecture

```text
  [ Local Host Sockets ]                 [ Firewall / Flow Logs ]
   Linux: /proc/net/*                     UFW / iptables / JSONL
   Windows: netstat -ano                           |
            |                                      v
            v                           +---------------------+
 +---------------------+                |  detector.ParseLine |
 | baseline.Collector  |                +---------------------+
 +---------------------+                           |
            |                                      v
            v                           +---------------------+
 +---------------------+                |  detector.Detector  |
 |  baseline.Auditor   | <-- YAML -->   |  (Bounded Window +  |
 |  (NET-001..NET-004) |    Policy      |  Cooldown Tracker)  |
 +---------------------+                +---------------------+
            |                                      |
            +------------------+-------------------+
                               |
                               v
                    +--------------------+
                    | schema.Report (v1) |
                    +--------------------+
                      |        |       |
            +---------+        |       +------------+
            v                  v                    v
      +-----------+      +-----------+       +-------------+
      |   Table   |      |   JSON    |       |  SARIF 2.1  |
      +-----------+      +-----------+       +-------------+
```

See [docs/architecture.md](docs/architecture.md) and [docs/threat-model.md](docs/threat-model.md) for package design details and threat assumptions.

## Installation

### Download Pre-built Binaries

Grab checksum-verified archives (`linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64`) from the [GitHub Releases](https://github.com/luminariadev/raksa-netguard/releases) page.

### Build from source (Go 1.26+)

```bash
git clone https://github.com/luminariadev/raksa-netguard.git
cd raksa-netguard
go build -o bin/raksa-netguard ./cmd/raksa-netguard
```

### Install via `go install`

```bash
go install github.com/luminariadev/raksa-netguard/cmd/raksa-netguard@latest
```

### Container (Non-root Distroless)

```bash
docker build -t raksa-netguard:local .
docker run --rm -v "$(pwd)/configs:/configs:ro" -v "$(pwd)/testdata:/testdata:ro" \
  raksa-netguard:local analyze --log /testdata/ufw_mixed.log --format table
```

## Quickstart

### 0. Generate a starter baseline and inspect rules (`init`, `rules`)

Bootstrap a YAML baseline directly from your current host sockets and inspect all built-in rules:

```bash
raksa-netguard init --host-role api-node --out baseline.yaml
raksa-netguard rules --format table
```

### 1. Validate a baseline policy (`policy-check`)

Lint a baseline YAML policy in pull requests before deploying it to hosts:

```bash
raksa-netguard policy-check --policy configs/baseline.example.yaml --fail-on high
```

Verified output on the bundled baseline:

```text
No findings detected by raksa-netguard.
Summary: total=0 critical=0 high=0 medium=0 low=0 info=0
```

### 2. Audit local listening sockets (`audit`)

Compare active host listeners against `configs/baseline.example.yaml`:

```bash
raksa-netguard audit --policy configs/baseline.example.yaml --format table
```

Example output:

```text
SEVERITY  RULE     TARGET                     TITLE
--------  ----     ------                     -----
HIGH      NET-002  tcp://0.0.0.0:135          Unauthorized listening port detected
HIGH      NET-002  tcp://[::]:135             Unauthorized listening port detected
MEDIUM    NET-002  tcp://127.0.0.1:1042       Unauthorized listening port detected
HIGH      NET-002  tcp://0.0.0.0:445          Unauthorized listening port detected
```

### 3. Analyze firewall or flow logs (`analyze`)

Detect vertical port scans, horizontal sweeps, connection bursts, and distributed multi-source scans across UFW, iptables, or JSONL logs. Pass `--policy` to load detector thresholds directly from your YAML baseline file:

```bash
raksa-netguard analyze --policy configs/baseline.example.yaml --log testdata/ufw_mixed.log --format table
```

Verified output:

```text
Analyzed 24 lines (23 events parsed, 1 skipped, 0 parse errors)
SEVERITY  RULE     TARGET                          TITLE
--------  ----     ------                          -----
HIGH      NET-101  ip://198.51.100.42->192.0.2.10  Vertical port scan detected
HIGH      NET-102  ip://203.0.113.19->*:22         Horizontal network scan detected

Summary: total=2 critical=0 high=2 medium=0 low=0 info=0
```

Distributed multi-source scan detection (`NET-104`) example:

```bash
raksa-netguard analyze --policy configs/baseline.example.yaml --log testdata/distributed_scan.jsonl --format table
```

```text
Analyzed 12 lines (12 events parsed, 0 skipped, 0 parse errors)
SEVERITY  RULE     TARGET             TITLE
--------  ----     ------             -----
HIGH      NET-104  host://192.0.2.50  Distributed multi-source port scan detected

Summary: total=1 critical=0 high=1 medium=0 low=0 info=0
```

JSON output (`--format json`) conforms to **Raksa Finding Schema v1**:

```bash
raksa-netguard analyze --log testdata/flows_scan.jsonl --format json --fail-on high
```

```json
{
  "schema_version": "1.0",
  "tool": "raksa-netguard",
  "layer": "network-defense",
  "generated_at": "2026-11-25T14:38:48.480572Z",
  "summary": {
    "total": 2,
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "id": "net-101-198-51-100-77-1795616714",
      "rule_id": "NET-101",
      "module": "scan-detector",
      "layer": "network-defense",
      "severity": "high",
      "title": "Vertical port scan detected",
      "description": "Source 198.51.100.77 probed 10 distinct destination ports on 192.0.2.20 within 1m0s.",
      "target": "ip://198.51.100.77->192.0.2.20",
      "evidence": {
        "dst_ip": "192.0.2.20",
        "sample_ports": [22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 6379],
        "src_ip": "198.51.100.77",
        "unique_ports": 10,
        "window": "1m0s"
      },
      "remediation": "Inspect firewall rules and consider temporarily blocking or rate-limiting source IP 198.51.100.77.",
      "mitre_d3fend": "D3-NTA",
      "timestamp": "2026-11-25T14:25:14Z"
    }
  ]
}
```

### 4. Tail live firewall logs with webhook alerts (`watch`)

Pass webhook URLs and bearer tokens via environment variables (`RAKSA_WEBHOOK_URL`, `RAKSA_WEBHOOK_TOKEN`) to avoid exposing credentials in process listings:

```bash
export RAKSA_WEBHOOK_URL="https://hooks.slack.com/services/..."
raksa-netguard watch \
  --log /var/log/ufw.log \
  --log-format ufw \
  --webhook-format slack \
  --window 60s \
  --cooldown 5m
```

## GitHub Actions & SARIF Integration

Upload baseline policy checks or host audit output directly to the GitHub Security tab:

```yaml
- name: Run raksa-netguard policy check
  run: |
    raksa-netguard policy-check \
      --policy configs/baseline.example.yaml \
      --format sarif > netguard.sarif

- name: Upload SARIF report
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: netguard.sarif
```

## Rule Reference & MITRE D3FEND Mapping

| Rule ID | Severity | Module | Condition | MITRE D3FEND |
| :--- | :--- | :--- | :--- | :--- |
| `NET-001` | `critical` / `high` | `baseline-auditor` | Port in `forbidden_ports` is actively listening | `D3-NI` |
| `NET-002` | `high` / `medium` | `baseline-auditor` | Active socket not listed in `allowed_ports` | `D3-HBPI` |
| `NET-003` | `high` | `baseline-auditor` | Socket bound to address outside `allowed_binds` | `D3-NI` |
| `NET-004` | `medium` | `baseline-auditor` | Sensitive service bound to wildcard without `allow_public: true` | `D3-NI` |
| `NET-010` | `high` | `baseline-auditor` | Policy permits sensitive port on wildcard without justification | `D3-HBPI` |
| `NET-011` | `high` | `baseline-auditor` | Policy permits insecure cleartext protocol (`ftp`, `telnet`, `tftp`, `rsh`) | `D3-NI` |
| `NET-101` | `high` | `scan-detector` | Vertical port scan across unique destination ports within window | `D3-NTA` |
| `NET-102` | `high` | `scan-detector` | Horizontal sweep across unique destination hosts on one port | `D3-NTA` |
| `NET-103` | `medium` | `scan-detector` | Connection attempt burst exceeding threshold within window | `D3-NTF` |
| `NET-104` | `high` | `scan-detector` | Distributed multi-source scan targeting one destination host | `D3-NTA` |

## Baseline Policy Schema

See [configs/baseline.example.yaml](configs/baseline.example.yaml) for a full annotated template:

```yaml
version: "1.0"
host_role: "web-api-node"

allowed_ports:
  - port: 5432
    protocol: tcp
    service: postgresql
    allowed_binds: ["127.0.0.1", "::1"]
    allow_public: false
    reason: "Database bound strictly to loopback"

forbidden_ports:
  - port: 23
    protocol: tcp
    reason: "Cleartext Telnet prohibited"
```

## MCP Server Integration (Agents & Tooling)

`raksa-netguard` exposes its defensive workflows natively over `stdio` JSON-RPC 2.0 via `raksa-netguard mcp`, allowing coding and security agents to inspect host exposure and analyze logs without fragile shell scraping.

Add `raksa-netguard` to any MCP-compatible client configuration:

```json
{
  "mcpServers": {
    "raksa-netguard": {
      "command": "raksa-netguard",
      "args": ["mcp"]
    }
  }
}
```

Exposed MCP tools:
- `netguard_list_rules`: Lists all `NET-*` rule IDs, severities, and MITRE D3FEND mappings.
- `netguard_check_policy`: Validates a baseline file (`policy_path`) or inline YAML (`policy_yaml`).
- `netguard_audit_host`: Audits active host listening sockets against a policy.
- `netguard_generate_baseline`: Generates a starter YAML baseline policy with review notes.
- `netguard_analyze_logs`: Runs sliding-window detection on `log_path` or `log_content` (`auto`, `ufw`, `iptables`, `nftables`, `windows-fw`, `jsonl`).

## Performance & Benchmarks

Measured on Windows/amd64 (Intel Core i5-11400H, Go 1.26.2):

| Benchmark / Workload | Speed | Allocations / Notes |
| :--- | :--- | :--- |
| `BenchmarkDetectorIngest` | **754.4 ns/op** (~1.32M events/s) | `80 B/op`, `3 allocs/op` |
| `BenchmarkAnalyzeUFW` (1,000 lines) | **2.66 ms/op** (~376k lines/s) | End-to-end parse + window tracking |
| `BenchmarkAnalyzeJSONL` (1,000 lines) | **3.45 ms/op** (~290k lines/s) | End-to-end JSON decode + window tracking |
| CLI `analyze` (100,000 JSONL lines, 14.6 MB) | **404 ms** (**~247k events/s**) | Full CLI startup, detection, and JSON serialization |

## Development & Testing

```bash
go vet ./...
go test -race -cover ./...
go test -bench=. -benchmem ./internal/detector/...
```

> Note: On Windows hosts without `gcc`/CGO enabled, run `go test -count=1 -cover ./...`; `-race` is enforced in Linux CI on every push and pull request.

## Raksa Security Suite

`raksa-netguard` is Layer 1 of the Raksa Blue Team & DevSecOps suite:

- **Layer 1 (`raksa-netguard`, Go)**: Network & perimeter defense (this repository)
- **Layer 2 (`raksa-hostguard`, Rust)**: Host integrity monitoring & Linux/Docker CIS auditing
- **Layer 3 (`raksa-webshield`, TypeScript + Go)**: Anti-XSS sanitization & HTTP security header auditing
- **Layer 4 (`raksa-pipeguard`, Go/Rust)**: Git secret scanning, OSV CVE auditing, IaC linting
- **Layer 5 (`raksa-iocscan`, Python)**: YARA rules, hash reputation, and static artifact triage
- **Layer 6 (`raksa-siem`, Python + Go)**: Log aggregation, correlation, and alerting

## License

[MIT](LICENSE)
