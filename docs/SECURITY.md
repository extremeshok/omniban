# Security Policy

## Reporting a vulnerability

Email **admin@extremeshok.com** with details and reproduction steps. Please do
not open a public issue for security reports. You will receive an acknowledgement
and a remediation timeline.

## Security posture

omniban runs as root and edits firewall, IDS, and system files, so it is built
defensively:

- **No shell injection.** External tools are invoked via `internal/exec.Runner`
  with arguments passed as a slice — never a shell string. The C locale is pinned
  for deterministic parsing.
- **Input validation.** Every user-controlled value (IP, CIDR, hostname, domain,
  duration) is validated in `internal/validate` before reaching a path, command
  argument, or file edit.
- **Owned-namespace safety.** omniban only writes to its own dedicated resources
  (nftables table, iptables chains, ipsets, the `/etc/hosts` managed block, the
  blackhole routes file). Other tools' resources are read for attribution only.
- **Never fights the IDS.** IDS-owned bans are removed through the IDS, avoiding
  orphaned or re-added rules.
- **Backups + undo.** Files are backed up before edits; mutations are recorded in
  an undo journal and an append-only, sanitized audit trail.
- **Lockout prevention.** Banning your current SSH client IP (or loopback, host
  IPs, gateway, or the configured admin allowlist) requires explicit `--force`.
- **Supply chain.** CI runs `gosec`, `govulncheck`, `gitleaks`, `hadolint`, and a
  dependency CVE scan; releases are checksummed.

## Supported versions

Pre-1.0: only the latest tagged release is supported.
