# omniban — implementation backlog

Milestones ship at production quality (tests, lint, security scan, docs). See
`docs/PRODUCTION_READINESS.md` for the v1.0.0 Definition of Done.

## M1 — Skeleton + CI + detection  (done)
- [x] Go module, `cmd/omniban` entrypoint, version stamping, signal handling
- [x] `internal/model`, `internal/exec` (Runner + FakeRunner), `internal/validate`
- [x] `internal/config` (koanf + owned-namespace constants), `internal/logging`, `internal/audit`
- [x] `internal/backend` interface + helpers + `Unimplemented`
- [x] 13 backend adapters with `Detect` + `Capabilities`
- [x] `internal/backend/all` registry
- [x] `internal/manager` detection, cross-warnings, manual-target selection
- [x] `internal/cli` root + `status` + `doctor` + `version` + `init`
- [x] hermetic unit tests (validate, exec, audit, config, crowdsec detect, manager)
- [x] Makefile, `.golangci.yml`, `.poll-ci.yml`, Dockerfile, AGENTS.md, docs, license
- [x] green local gate: build, vet, golangci-lint, `go test -race`, coverage

## M2 — IDS backends RW + search + safety  (done)
- [x] `internal/resolve`: hostname→IP + match engine (exact / CIDR-contains / glob)
- [x] `internal/safety`: lockout guard (protected set) + undo journal
- [x] CrowdSec: list/ban/unban via `cscli decisions`, allowlists, golden fixtures
- [x] fail2ban: per-jail list + all-jails/per-jail unban, golden fixtures
- [x] sshguard: whitelist allow/remove + best-effort nft list/unban
- [x] CSF: list/ban/unban/allow via `csf`, file parsing
- [x] APF/BFD: list/ban/unban/allow via `apf`, BFD attribution
- [x] denyhosts: list/ban/unban (daemon coordination + backups), allowed-hosts
- [x] CLI: `list`, `check`, `ban`, `unban`, `allow`, `unallow`, `undo` (+ `--dry-run`/`--json`)
- [x] manager dedup/attribution + audit + undo + lockout guard

## M3 — Firewall/enforcement RW  (done)
- [x] UFW (by-spec deny/allow + delete), firewalld (permanent rich rules + reload)
- [x] raw nftables (own table `inet omniban`, deny4/deny6 sets + drop rule)
- [x] raw iptables (own chain OMNIBAN_INPUT, v4+v6)
- [x] ipset (own sets omniban-deny4/6 + idempotent referencing DROP rule)
- [x] owned-namespace safety (only ever writes omniban's own objects); golden fixtures + tests
- [ ] follow-up: foreign-enforcement scan to populate AlsoSeenIn; reboot persistence for raw nft/iptables/ipset via `omniban apply`

## M4 — Routing/DNS mechanisms  (done)
- [x] blackhole null-route + `apply-routes` + systemd oneshot persistence (own routes file)
- [x] `/etc/hosts` sinkhole: whole-file scan (managed vs External), managed-block adds, surgical remove, backups
- [x] `sinkhole` / `null-route` CLI; Direction surfaced in list/check

## M5 — TUI  (done)
- [x] bubbletea bans/allowlist/status views; filter; async refresh; unban confirm modal
- [x] `tui` command + interactive launch on no-subcommand
- [ ] follow-up: ban/allow input modals in the TUI (CLI covers these today)

## M6 — Packaging/release/docs  (done, pending VPS validation)
- [x] goreleaser + nfpm: static amd64/arm64 binaries + .deb/.rpm + checksums (snapshot verified)
- [x] install script; release workflow; systemd unit; full docs
- [ ] tag v1.0.0 after poll-ci on the CI VPS + live per-distro e2e

## M7 — Live container e2e for all backends  (done)
- [x] `test/e2e/` suite + `make e2e`: real-tool e2e in privileged containers
- [x] live (all 13): nftables, iptables, ipset, blackhole, hosts, ufw, sshguard, denyhosts, apf, fail2ban (daemon), crowdsec (LAPI), csf (enabled), firewalld (dbus)
- [x] bugs found+fixed live: unban-domain DNS, apf `-u` file cleanup, crowdsec alert-wrapped JSON parser
- [ ] multi-distro confirmation (AlmaLinux/CloudLinux/Proxmox) via E2E_IMAGE on the VPS

## Roadmap (post-1.0)
- [ ] Wazuh/OSSEC active-response; Shorewall; FireHOL/update-ipsets; pve-firewall
- [ ] CrowdSec `pkg/apiclient`; threat-feed import; auto-expiry daemon
- [ ] foreign-enforcement scan for AlsoSeenIn; reboot persistence for raw nft/iptables/ipset; TUI ban/allow modals
