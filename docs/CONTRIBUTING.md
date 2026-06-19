# Contributing to omniban

Read [`AGENTS.md`](../AGENTS.md) first — it is the binding contribution guide for
humans and automated contributors alike. Highlights:

- **No AI attribution and no emoji** anywhere (code, comments, commits, PRs, docs).
  The human operator is the sole author on record.
- Validate untrusted input; never build shell strings; never fight the IDS; only
  write to omniban's own namespaces; honor `--dry-run`; back up before editing.

## Development

```sh
make all            # gofmt, go vet, golangci-lint, go test -race
make test           # go test -race ./...
make coverage-check # enforce the coverage floor
make build          # static binary into ./bin/omniban
```

Requires Go 1.26+. Install the linters/scanners with:

```sh
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```

## Tests

- Unit tests are **hermetic**: use `internal/exec.FakeRunner` to replay golden
  fixtures captured from real tool output — no root, no real tools. This is what
  `poll-ci` gates on.
- Live integration tests against real tools are tagged `//go:build integration`
  and run on a VPS.

## Adding a backend

See the "Adding a backend" section of [`AGENTS.md`](../AGENTS.md): create the
adapter package, register it in `internal/backend/all`, add golden fixtures and
table-driven tests, and route any host file edits through `internal/persist`.

## Git

- Branches: `feat/…`, `fix/…`, `refactor/…`, `chore/…`.
- Conventional subjects under 72 chars; semver tags `vX.Y.Z`.
- Include a Test plan in the PR body listing what you actually ran.
