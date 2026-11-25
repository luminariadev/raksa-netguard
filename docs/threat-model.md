# raksa-netguard Threat Model

## Defensive Scope

`raksa-netguard` is built for defenders, SREs, and DevSecOps engineers to verify local host network exposure and detect reconnaissance activity directed at their own infrastructure.

### In Scope
- Auditing locally bound TCP/UDP listening sockets against an explicit, version-controlled baseline YAML policy.
- Detecting configuration drift such as services accidentally binding to `0.0.0.0` or `::` instead of `127.0.0.1` or private interfaces.
- Identifying overly permissive baseline policies before deployment (`policy-check`).
- Analyzing local firewall logs (UFW/iptables) and structured flow logs (JSONL) for vertical port scans, horizontal sweeps, and connection bursts.

### Out of Scope (Non-Goals)
- **Active network probing**: `raksa-netguard` never sends packets to remote hosts, performs SYN/TCP port scans, or enumerates external targets.
- **Inline packet blocking**: The tool is an observer and auditor. Enforcement remains the responsibility of host firewalls (`nftables`, `ufw`, `iptables`, Windows Defender Firewall) or orchestrators.
- **Deep packet inspection (DPI)**: Analysis operates on socket metadata and firewall/flow log records, not application payloads.

## Assumptions & Trust Boundaries

1. **Local Socket Visibility**:
   - On Linux, `/proc/net/*` is world-readable for socket addresses/ports, while process names or PIDs belonging to other users may require elevated privileges depending on `hidepid` mount options.
   - On Windows, `netstat -ano` returns local listening sockets and owning PIDs without requiring administrator elevation.
2. **Log Integrity**:
   - Detection accuracy assumes the host logging daemon (`rsyslog`, `journald`, or flow exporter) accurately records source/destination metadata and has not been tampered with locally.
   - Spoofed source IP addresses in raw unestablished UDP/SYN logs can trigger alerts on the spoofed IP; treat `NET-101`..`NET-103` findings as triage signals rather than blind auto-ban triggers without context.
3. **Sensitive Configuration & Secrets**:
   - Webhook alert URLs (Slack, Discord, or internal SOAR endpoints) may contain bearer credentials in URLs or headers. Pass `--webhook` or auth tokens via environment variables or secret managers rather than committing them to YAML policies.

## Operational Hardening Notes

- Run the container image with the bundled non-root distroless user whenever analyzing mounted logs or policies.
- Pin baseline YAML files in Git and enforce `raksa-netguard policy-check --fail-on high` in pull request checks so permissive wildcard rules are reviewed explicitly.
- Configure reasonable `--cooldown` intervals on `watch` mode to prevent webhook alert amplification during noisy internet background scans.
