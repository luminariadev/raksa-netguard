# raksa-netguard Architecture

`raksa-netguard` is the Layer 1 (Network Defense) component of the Raksa security suite. It operates purely defensively on the local host and local telemetry streams through two independent pipelines that converge on a unified reporting and notification interface.

## Component Flow

```
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
 |  baseline.Auditor   | <-- YAML -->   |  (Sliding Window +  |
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
                               |
                               v
                    +--------------------+
                    | notifier.Webhook   | (optional on watch)
                    +--------------------+
```

## Package Responsibilities

- `cmd/raksa-netguard`: Subcommand entrypoint (`audit`, `policy-check`, `analyze`, `watch`, `version`), `--fail-on` CI gate exit codes, and `SIGINT`/`SIGTERM` lifecycle management.
- `internal/schema`: Canonical Raksa Finding Schema v1 data structures, severity ranking, and summary aggregation.
- `internal/baseline`:
  - `policy.go`: Parses and validates YAML baseline definitions (`NET-010`, `NET-011`) and optional detector thresholds.
  - `collector.go`: Cross-platform local listening socket collector. Uses direct `/proc/net/{tcp,tcp6,udp,udp6}` hex parsing on Linux and `netstat -ano` parsing on Windows.
  - `process.go`: Best-effort process-name enrichment using `/proc/<pid>/fd` + `/proc/<pid>/comm` on Linux and `tasklist /FO CSV /NH` on Windows.
  - `auditor.go`: Evaluates active host listeners against policy rules (`NET-001` through `NET-004`) with bind-address, sensitive-port, and process metadata checks.
- `internal/detector`:
  - `logparser.go`: Normalizes UFW, iptables, and JSONL flow events into typed network records.
  - `detector.go`: Thread-safe per-source and per-target bounded sliding-window tracker detecting vertical port scans (`NET-101`), horizontal host sweeps (`NET-102`), connection bursts (`NET-103`), and distributed multi-source scans (`NET-104`) with cooldown suppression.
  - `watcher.go`: File tailing loop supporting copytruncate truncation and inode replacement rotation detection.
- `internal/report`: Serializes `schema.Report` into terminal tables, Raksa JSON v1, or SARIF 2.1.0 for GitHub Code Scanning.
- `internal/notifier`: Deduplicated HTTP webhook dispatcher supporting generic JSON, Slack, and Discord payloads with retry on `5xx`.

## MITRE D3FEND Coverage

| Rule ID | Detection / Hardening Control | MITRE D3FEND | Technique Name |
| :--- | :--- | :--- | :--- |
| `NET-001` | Forbidden listening port exposure | `D3-NI` | Network Isolation |
| `NET-002` | Unauthorized listening service drift | `D3-HBPI` | Host-Based Port Inspection |
| `NET-003` | Overly permissive wildcard bind (`0.0.0.0`/`::`) | `D3-NI` | Network Isolation |
| `NET-004` | Sensitive database/admin port exposed publicly | `D3-NI` | Network Isolation |
| `NET-010` | Unjustified public bind in baseline policy | `D3-HBPI` | Host-Based Port Inspection |
| `NET-011` | Insecure cleartext protocol allowed in policy | `D3-NI` | Network Isolation |
| `NET-101` | Vertical port scan pattern in local logs | `D3-NTA` | Network Traffic Analysis |
| `NET-102` | Horizontal host sweep pattern in local logs | `D3-NTA` | Network Traffic Analysis |
| `NET-103` | Connection burst / flood anomaly in local logs | `D3-NTF` | Network Traffic Filtering |
| `NET-104` | Distributed multi-source scan targeting a host | `D3-NTA` | Network Traffic Analysis |
