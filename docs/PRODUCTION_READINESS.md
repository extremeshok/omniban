# omniban — Production Readiness

## v1.0.0 Definition of Done

- [x] All 13 backends detected and **read/write** (list + search + unban
      everywhere; ban/allow per capability): CrowdSec, fail2ban, sshguard,
      CSF/LFD, APF/BFD, denyhosts, UFW, firewalld, raw nftables, raw iptables,
      ipset, blackhole routes, `/etc/hosts` sinkhole.
- [x] Unified list with source + direction labels, dedup/attribution, and
      owned-namespace safety (omniban never writes foreign objects).
- [x] `check` search: exact, CIDR-contains, wildcard/glob, hostname.
- [x] Add by IP / CIDR / hostname / domain; `sinkhole` and `null-route` with
      boot persistence (`apply-routes` + systemd oneshot).
- [x] Safety: lockout guard, undo journal, audit trail, dry-run, file backups.
- [x] TUI + full CLI; `doctor`/`status` health and warnings.
- [x] `AGENTS.md` honored (no AI attribution, no emoji).
- [x] Packaging: goreleaser builds static amd64/arm64 binaries + `.deb`/`.rpm` +
      checksums (snapshot verified); install script; systemd unit.
- [x] Local gate green: gofmt, `go build`, `go vet`, `golangci-lint` (0 issues),
      `go test -race`, coverage (~60%).
- [ ] poll-ci green on the CI VPS (gitleaks/hadolint/trivy run there) — pending the CI image build.
- [ ] Live e2e on the provided VPS across the target distros.
- [ ] Follow-ups: foreign-enforcement scan to populate AlsoSeenIn; reboot
      persistence for raw nft/iptables/ipset; TUI ban/allow input modals.

## Current state

**M1–M6 implemented locally and green.** Foundation (`model`, `exec`,
`validate`, `config`, `logging`, `audit`, `resolve`, `safety`); the backend
interface + 13 read/write adapters with golden fixtures; the `manager`
(detection, dedup/attribution, action routing, audit, undo, lockout guard); the
full CLI (`status`/`doctor`/`list`/`check`/`ban`/`unban`/`allow`/`unallow`/
`sinkhole`/`null-route`/`apply-routes`/`undo`/`init`/`version`); the Bubble Tea
TUI; and the goreleaser/nfpm release pipeline.

Remaining before tagging v1.0.0: run the poll-ci gate on the CI VPS and the live
per-distro e2e (the maintainer is providing a VPS). See `TODO.md` for follow-ups.

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
