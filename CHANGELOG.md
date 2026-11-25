# Changelog

All notable changes to `raksa-netguard` are documented in this file.

## [0.2.0] - 2026-11-25

### Added
- **Process-Name Enrichment (`audit`)**: Resolves socket inode ownership via `/proc/<pid>/fd` and `/proc/<pid>/comm` on Linux and `tasklist /FO CSV /NH` on Windows, enriching `evidence.process` and remediation hints.
- **Distributed Multi-Source Scan Detection (`NET-104`)**: Added a bounded per-target sliding window to flag coordinated probes from multiple distinct source IPs across distinct destination ports on a single host (`D3-NTA`), backed by `testdata/distributed_scan.jsonl`.
- **Policy-Driven Detector Defaults**: Added `--policy`, `--distributed-sources`, and `--distributed-ports` to `analyze` and `watch`, reading `detector:` settings from YAML baseline policies with explicit CLI flag precedence.
- **Automated Release Workflow**: Added `.github/workflows/release.yml` for tagged `v*` releases building cross-platform archives (`linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64`) and `SHA256SUMS.txt`.

### Changed
- Upgraded GitHub Actions workflow actions to `actions/checkout@v7` and `actions/setup-go@v7` (Node 24 native) tracking latest `go-version: '1.26.x'` patches for `govulncheck`.
- Hardened `WatchFile` log rotation recovery with `os.SameFile` inode replacement detection.

## [0.1.0] - 2026-11-25

### Added
- Initial release of `raksa-netguard` with `audit`, `policy-check`, `analyze`, `watch`, and `version` subcommands.
- Cross-platform local listener collection (`/proc/net/*` on Linux, `netstat -ano` on Windows) and YAML baseline drift rules `NET-001`..`NET-004` and `NET-010`..`NET-011`.
- Sliding-window UFW/iptables and JSONL detector rules `NET-101` (vertical scan), `NET-102` (horizontal sweep), and `NET-103` (connection burst) with bounded source tracking and IPv4/IPv6 canonicalization.
- Table (ANSI-sanitized), Raksa Finding Schema v1 JSON, and SARIF 2.1.0 formatters plus HTTP webhook sink (`generic`, `slack`, `discord`).
- Non-root distroless `Dockerfile` and GitHub Actions CI.
