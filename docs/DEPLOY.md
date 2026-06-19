# omniban — Deployment

omniban manages the host firewall directly, so it installs as a native binary or
package on the host (not in a container). It must run as root.

## Install

### Package (recommended)

```sh
# Debian / Ubuntu / Proxmox
sudo dpkg -i omniban_<version>_linux_amd64.deb

# RHEL clones / AlmaLinux / Rocky / CloudLinux
sudo rpm -i omniban_<version>_linux_amd64.rpm
```

### Install script

```sh
curl -fsSL https://raw.githubusercontent.com/extremeshok/omniban/master/scripts/install.sh | sudo bash
```

### From source

```sh
git clone https://github.com/extremeshok/omniban
cd omniban
make build && sudo make install   # installs /usr/local/bin/omniban
```

## First run

```sh
sudo omniban init      # write /etc/omniban/config.yaml
sudo omniban doctor    # confirm detection and review warnings
```

Key warnings to act on:
- **CrowdSec running without a bouncer** — decisions are not being enforced.
- **Multiple active firewalls** — set `manual_ban_backend` to choose the target.
- **denyhosts IPv6** — manage IPv6 bans via a firewall backend.

## Blackhole route persistence

The `.deb`/`.rpm` install `omniban-routes.service`. Enable it so null-routes
survive a reboot:

```sh
sudo systemctl enable omniban-routes.service
```

## CI on a VPS (poll-ci)

CI runs via [`extremeshok/poll-ci`](https://github.com/extremeshok/poll-ci):

1. Build and publish the toolchain image: `docker build -t ghcr.io/extremeshok/omniban-ci:latest -f ci/Dockerfile .`
2. Point poll-ci at this repo; it reads `.poll-ci.yml`, runs the gate on each
   commit to `master`, reports commit statuses, and fast-forwards `release` on
   green.

## Paths

- Config: `/etc/omniban/config.yaml`
- Audit log: `/var/log/omniban.log` (JSON lines, `0640 root:adm`)
- State (undo journal, blackhole routes): `/var/lib/omniban/`, `/etc/omniban/blackhole-routes.conf`
