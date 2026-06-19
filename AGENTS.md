# AGENTS.md — guidance for AI / code-assistant contributions

This file documents the conventions this codebase expects from automated
contributors (and humans). It applies to anyone editing backends, the CLI/TUI,
or the build/CI tooling. It mirrors the house rules from the author's other
projects, adapted to Go.

## No AI branding — zero exceptions

No AI-agent branding, attribution, or mention, anywhere:

- Source code (Go, shell, YAML) — no AI tool names in comments, banners, identifiers.
- Commit messages — no `Co-Authored-By:` AI trailers, no "Generated with …", no emoji tags, no tool signatures.
- PR / issue text — no "created with", "authored by", "with the help of".
- Docs, config, log lines, user-facing strings.

The human operator is the sole author on record. If you spot a violation in
files or commit history, remove it.

## No emoji

Not in code, comments, commit messages, PR bodies, docs, or user-facing output.
omniban runs headless and is piped through non-UTF8 terminals.

## Golden rules

1. **Lint clean.** `golangci-lint run ./...` and `go vet ./...` must pass.
   `gofmt`/`goimports` formatted. Keep functions small and the "why" in comments.
2. **Validate untrusted input.** Every user-controlled string that reaches a
   filesystem path, an external command argument, or a config position goes
   through `internal/validate`. Never build a shell string from user input —
   always pass arguments as a slice via `internal/exec.Runner` (no shell).
3. **Never fight the automation.** An IDS (fail2ban, CrowdSec, sshguard, CSF,
   APF/BFD, denyhosts) owns the bans it creates. Unban through its native API,
   not by deleting the downstream firewall rule, or it will re-add the ban.
4. **Owned-namespace safety.** omniban only writes to its own resources
   (`config.Nft*`, `config.Iptables*`, `config.IPSet*`, the `/etc/hosts` managed
   block, the blackhole routes file). Foreign resources (`f2b-*`, `crowdsec-*`,
   `fw-*`, sshguard) are read for attribution only — never modified.
   See `config.IsForeignResource`.
5. **Back up before editing an existing file** (`/etc/hosts`, denyhosts files,
   persistence files) and record an undo entry. Config writers that create a
   brand-new file need no backup.
6. **Dry-run everywhere.** Every mutating code path must honor `--dry-run`,
   returning the exact planned command(s)/edits in `model.Result.Commands`
   without executing them.
7. **Sanitize log/audit fields** via `audit.Sanitize` (strips CR/LF/ESC). Never
   interpolate raw untrusted strings into log lines.
8. **Lockout prevention.** A ban touching the protected set (current SSH client
   IP, loopback, host IPs, gateway, `admin_allowlist`) requires confirmation in
   the TUI and `--force` in the CLI.

## Repository layout

```
cmd/omniban/            entrypoint + version stamping
internal/model/         backend-agnostic domain types
internal/exec/          Runner interface + OS impl + FakeRunner (test double)
internal/validate/      untrusted-input validators
internal/config/        koanf config + owned-namespace constants
internal/logging/       slog setup
internal/audit/         JSON-lines audit trail + sanitization
internal/safety/        lockout guard, undo (M2)
internal/resolve/       hostname resolution + match engine (M2)
internal/persist/       per-distro persistence + file edits (M3/M4)
internal/backend/       Backend interface + detection helpers
internal/backend/<x>/   one adapter per mechanism (+ testdata/ golden files)
internal/backend/all/   registry (imports every adapter; avoids an import cycle)
internal/manager/       detection, unified view, attribution, action routing
internal/cli/           cobra command tree
internal/tui/           bubbletea app (M5)
```

## Adding a backend

1. Create `internal/backend/<name>/<name>.go`, embed `backend.Unimplemented`,
   implement `Name`, `Capabilities`, `Detect`, and the operations it supports.
2. Register it in `internal/backend/all/all.go`.
3. Add golden fixtures under `internal/backend/<name>/testdata/` (real tool
   output) and table-driven parser tests using `exec.FakeRunner` — no root, no
   real tools.
4. If it writes to the host, route file edits through `internal/persist`
   (lock + backup) and respect owned-namespace safety.

## Testing

- Unit tests are hermetic: `exec.FakeRunner` replays golden fixtures; no root,
  no real tools. This is what `poll-ci` gates on.
- `go test -race ./...` and `make coverage-check` must pass.
- Live integration tests against real tools are tagged `//go:build integration`
  and run on a VPS, not in the poll-ci container.

## Git conventions

- Branches: `feat/…`, `fix/…`, `refactor/…`, `chore/…`.
- Conventional-ish subjects under 72 chars (`feat:`, `fix:`, `docs:`, …).
- Semver tags `vMAJOR.MINOR.PATCH`; the version is stamped via ldflags.
- No emoji. No AI attribution. No `Co-Authored-By` AI trailers.

## Session bootstrap

Read in order: `AGENTS.md` → `TODO.md` → `docs/PRODUCTION_READINESS.md`.
