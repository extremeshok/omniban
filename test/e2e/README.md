# Live e2e

These suites exercise omniban against **real** tools, complementing the hermetic
unit tests (which replay golden fixtures). A cross-built Linux binary runs inside
a privileged Linux container so netfilter/file operations are real.

```sh
make e2e                          # all scenarios, debian:bookworm-slim
./test/e2e/run.sh                 # same
./test/e2e/run.sh ufw_e2e.sh      # one scenario
E2E_IMAGE=almalinux:9 ./test/e2e/run.sh netfilter_e2e.sh
```

`run.sh` cross-builds `cmd/omniban`, then runs each `*_e2e.sh` in a fresh
privileged container with the binary mounted at `/usr/local/bin/omniban`.

## Scenarios

| Scenario | Real tool exercised | Notes |
|---|---|---|
| `netfilter_e2e.sh` | nftables, iptables, ipset, blackhole routes, `/etc/hosts` | own table/chain/set; lockout guard; dry-run; undo; audit |
| `fail2ban_e2e.sh` | fail2ban daemon | list/check + unban via `fail2ban-client` |
| `ufw_e2e.sh` | ufw | deny/allow + by-spec delete |
| `denyhosts_e2e.sh` | DenyHosts file layout | deprecated package; real `/etc/hosts.deny` + work files + allowed-hosts |
| `sshguard_e2e.sh` | sshguard whitelist + its nftables set | allowlist file + the `ip sshguard`/`attackers` set the daemon maintains |
| `crowdsec_e2e.sh` | CrowdSec cscli + Local API | tolerant install (the `.deb` postinst needs systemd); LAPI runs as a process |
| `csf_e2e.sh` | ConfigServer Firewall | installs from source; needs network to `download.configserver.com` |
| `apf_e2e.sh` | Advanced Policy Firewall | installs from source (rfxn.com) |

Requires Docker with privileged containers (kernel netfilter access). A handful
of scenarios install from the network; they print `SKIP: …` and exit cleanly if
a download/registry is unreachable from the build environment (e.g. the
ConfigServer host or Docker Hub rate limits), so a sandbox network restriction
never masquerades as an omniban failure.
