# Live e2e

These suites exercise omniban against **real** tools, complementing the hermetic
unit tests (which replay golden fixtures). A cross-built Linux binary runs inside
a privileged Linux container so netfilter/dbus/file operations are real.

```sh
make e2e                          # all scenarios, debian:bookworm-slim
./test/e2e/run.sh                 # same
./test/e2e/run.sh ufw_e2e.sh      # one scenario
E2E_IMAGE=almalinux:9 ./test/e2e/run.sh netfilter_e2e.sh
```

`run.sh` cross-builds `cmd/omniban`, then runs each `*_e2e.sh` in a fresh
privileged container with the binary mounted at `/usr/local/bin/omniban`.

## Scenarios (all 19 backends, real tools)

| Scenario | Real tool exercised | Notes |
|---|---|---|
| `netfilter_e2e.sh` | nftables, iptables, ipset, blackhole routes, `/etc/hosts` | own table/chain/set; lockout guard; dry-run; undo; audit |
| `fail2ban_e2e.sh` | fail2ban daemon | list/check + unban via `fail2ban-client` |
| `crowdsec_e2e.sh` | CrowdSec cscli + Local API | tolerant install (postinst needs systemd); LAPI runs as a process |
| `csf_e2e.sh` | ConfigServer Firewall (enabled) | assembled release tarball; `cron` for `/etc/crontab`; TESTING off so chains exist |
| `apf_e2e.sh` | Advanced Policy Firewall | installs from source (rfxn.com) |
| `denyhosts_e2e.sh` | DenyHosts file layout | deprecated package; real `/etc/hosts.deny` + work files + allowed-hosts |
| `sshguard_e2e.sh` | sshguard whitelist + its nftables set | allowlist file + the `ip sshguard`/`attackers` set the daemon maintains |
| `ufw_e2e.sh` | ufw | deny/allow + by-spec delete |
| `firewalld_e2e.sh` | firewalld daemon (over dbus) | iptables backend (nftables backend stalls in containers); rich rules + reload |
| `suricata_e2e.sh` | Suricata unix-command socket | `suricatasc` dataset-add/remove/lookup; ListBans parses the dataset save file (from bookworm-backports) |
| `wazuh_e2e.sh` | Wazuh `firewall-drop` active response | stateful two-message handshake over the AR socket; verifies the iptables DROP it installs + `active-responses.log` |
| `shorewall_e2e.sh` | Shorewall dynamic blacklist | `shorewall drop`/`allow`/`show dynamic`; needs `/var/log/messages` present |
| `haproxy_e2e.sh` | HAProxy runtime API | `add map`/`del map`/`show map` over the stats socket via `socat` |
| `modsecurity_e2e.sh` | nginx + ModSecurity v3 | `@ipMatchFromFile` blocklist + `nginx -s reload`; asserts a real 403 for a blocked client |
| `bunkerweb_e2e.sh` | BunkerWeb `bwcli` | SKIPs without the full scheduler+datastore stack; adapter is unit-tested |

Requires Docker with privileged containers (kernel netfilter / dbus access).
Scenarios that install from the network print `SKIP: …` and exit cleanly if a
download/registry is unreachable from the build environment (e.g. Docker Hub
rate limits), so a sandbox network restriction never masquerades as a failure.
`CSF_TGZ` (csf) and `E2E_IMAGE` (base image) can be overridden.
