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

## M2 — IDS backends RW + search + safety
- [ ] `internal/resolve`: hostname→IP + match engine (exact / CIDR-contains / glob)
- [ ] `internal/safety`: lockout guard (protected set), confirmation, undo journal
- [ ] CrowdSec: list/ban/unban via `cscli decisions`, allowlists, golden fixtures
- [ ] fail2ban: per-jail list/ban/unban, ignoreip allow, golden fixtures
- [ ] sshguard: list/ban/unban via nft set, whitelist file
- [ ] CSF: list/ban/unban/allow via `csf`, file parsing
- [ ] APF/BFD: list/ban/unban/allow via `apf`, BFD attribution
- [ ] denyhosts: list/ban/unban (daemon coordination + backups), allowed-hosts
- [ ] CLI: `list`, `check`, `ban`, `unban`, `allow`, `unallow` (+ `--dry-run`/`--json`)
- [ ] manager dedup/attribution v1; wire audit + undo

## M3 — Firewall/enforcement RW
- [ ] UFW, firewalld, raw nftables (own table), raw iptables (own chain)
- [ ] ipset (own sets + ensure referencing rule)
- [ ] `internal/persist`: per-distro persistence; foreign-namespace safety; AlsoSeenIn

## M4 — Routing/DNS mechanisms
- [ ] blackhole null-route + `apply-routes` + systemd oneshot persistence
- [ ] `/etc/hosts` sinkhole: whole-file scan, managed-block adds, surgical remove, backups
- [ ] Direction surfaced in list/check

## M5 — TUI
- [ ] bubbletea bans/allowlist/status views; search & action modals; filter/sort; async refresh

## M6 — Packaging/release/docs
- [ ] goreleaser + nfpm (.deb/.rpm); install script; release workflow
- [ ] full docs; tag v1.0.0; e2e on VPS

## M7 — Roadmap
- [ ] Wazuh/OSSEC active-response; Shorewall; FireHOL/update-ipsets; pve-firewall
- [ ] CrowdSec `pkg/apiclient`; threat-feed import; auto-expiry daemon
