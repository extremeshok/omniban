# omniban

**One ban manager for every Linux firewall & IDS.**

`omniban` is a single TUI/CLI to view, search, and manage IP bans, domain
sinkholes, and null-routes across every firewall and intrusion-defense tool on a
Linux server. It auto-detects what's installed, shows every ban tagged by its
source and direction, and adds/removes/whitelists through the correct native
backend — so you never fight your IDS or clobber another tool's rules.

> Status: early development. M1 (skeleton, backend detection, `status`/`doctor`,
> CI gate) is complete. Read/write management of each backend lands across
> M2–M4. See [`TODO.md`](TODO.md) and [`docs/PRODUCTION_READINESS.md`](docs/PRODUCTION_READINESS.md).

## Why

A typical server runs several overlapping ban mechanisms that each have their own
CLI, data store, and quirks — and they layer on top of each other (an IDS creates
a ban that is enforced inside a firewall). `omniban` unifies them behind one
interface and one mental model.

## Supported backends (v1)

| Layer | Backends |
|-------|----------|
| IDS / detection | CrowdSec, fail2ban, sshguard, CSF/LFD, APF/BFD, denyhosts |
| Firewall / enforcement | UFW, firewalld, raw nftables, raw iptables, ipset |
| Routing / DNS | blackhole null-routes (`ip route`), `/etc/hosts` sinkholes |

Targets Ubuntu, Debian, RHEL clones (AlmaLinux/Rocky), CloudLinux, and Proxmox.
Roadmap: Wazuh/OSSEC, Shorewall, FireHOL, Proxmox pve-firewall, threat-feed import.

## Design principles

- **Source-labeled.** Every ban shows its true owner; unbans route to that owner.
- **Never fight the automation.** An IDS-created ban is removed via the IDS, not
  by deleting the downstream firewall rule.
- **Never clobber.** omniban only writes to its own dedicated namespaces; other
  tools' sets/chains/rules are read for attribution only.
- **Safe by default.** Dry-run previews, an audit trail, an undo journal, backups
  before editing files, and a lockout guard that refuses to ban your own SSH IP.

## Install

Native package or single static binary (a firewall manager must run on the host,
not in a container):

```sh
# Debian/Ubuntu
sudo dpkg -i omniban_*_linux_amd64.deb
# RHEL/AlmaLinux/Rocky/CloudLinux
sudo rpm -i omniban_*_linux_amd64.rpm
```

Or build from source (Go 1.26+):

```sh
make build && sudo make install
```

## Usage

```sh
sudo omniban status            # detected backends and their state
sudo omniban doctor            # health check + warnings
sudo omniban list              # every ban/allow, source- and direction-labeled   (M2)
sudo omniban check 1.2.3.4 --contains   # is this blocked anywhere?               (M2)
sudo omniban ban evil.example.com --duration 4h                                   # (M2)
sudo omniban unban 1.2.3.4 --via denyhosts                                        # (M2)
sudo omniban sinkhole ads.example.com                                             # (M4)
sudo omniban null-route 203.0.113.0/24                                            # (M4)
```

Run `sudo omniban` with no arguments for the interactive TUI (M5).

## Development

```sh
make all          # fmt, vet, lint, test
make test         # go test -race
make coverage-check
make lint         # golangci-lint
```

Contributor conventions — including the no-AI-attribution and no-emoji rules —
are in [`AGENTS.md`](AGENTS.md). CI runs via [`extremeshok/poll-ci`](.poll-ci.yml).

## License

BSD 3-Clause. Coded by Adrian Jon Kriel :: admin@extremeshok.com
