# omniban — Production Readiness

## v1.0.0 Definition of Done

- [ ] All v1 backends detected and **fully read/write** (list + search + unban
      everywhere; ban/allow per capability):
      CrowdSec, fail2ban, sshguard, CSF/LFD, APF/BFD, denyhosts, UFW, firewalld,
      raw nftables, raw iptables, ipset, blackhole routes, `/etc/hosts` sinkhole.
- [ ] Unified list with source + direction labels, dedup/attribution, and
      foreign-namespace safety.
- [ ] `check` search: exact, CIDR-contains, wildcard/glob, hostname.
- [ ] Add by IP / CIDR / hostname / domain; `sinkhole` and `null-route` with boot
      persistence.
- [ ] Safety: lockout guard, undo journal, audit trail, dry-run, file backups.
- [ ] TUI + full CLI; `doctor`/`status` health and warnings.
- [ ] `AGENTS.md` honored (no AI attribution, no emoji).
- [ ] All `poll-ci` checks green + trivy clean; packaging (.deb/.rpm + installer);
      docs; e2e verified on the VPS.

## Current state

**M1 complete:** module skeleton, version stamping, signal handling; foundational
packages (`model`, `exec`, `validate`, `config`, `logging`, `audit`); the backend
interface plus 13 adapters implementing `Detect`/`Capabilities`; the registry and
`manager` (detection, cross-warnings, manual-target selection); CLI `status`,
`doctor`, `version`, `init`; hermetic unit tests; and a green local gate (build,
vet, golangci-lint, `go test -race`, coverage).

Read/write management of each backend lands in M2–M4. See `TODO.md`.

## Architecture

Two-layer model: an **IDS layer** (fail2ban, CrowdSec, sshguard, CSF, APF/BFD,
denyhosts) *creates* bans which are *enforced* by a **firewall layer** (UFW,
firewalld, nftables, iptables, ipset, CSF). Plus **routing/DNS** mechanisms
(blackhole routes, `/etc/hosts`). A single IP can appear in both layers; omniban
attributes each entry to its owner (IDS wins) and routes unbans accordingly.

## Key files

- `internal/backend/` — adapter contract, helpers, 13 adapters, registry (`all/`).
- `internal/manager/` — detection, attribution, action routing.
- `internal/config/namespace.go` — owned-namespace constants + `IsForeignResource`.
- `internal/safety/` — lockout guard + undo (M2).
- `internal/exec/` — `Runner` + `FakeRunner` (the basis of hermetic tests).
- `.poll-ci.yml`, `ci/Dockerfile` — the CI gate and its toolchain image.

## Operational invariants

- Runs as root; refuses non-root for mutating/most read commands.
- Never modifies another tool's sets/chains/rules (attribution-only).
- Never removes an IDS-owned ban by deleting the downstream firewall rule.
- Every mutation supports `--dry-run` and is recorded in the audit trail.
