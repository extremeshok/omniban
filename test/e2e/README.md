# Live e2e

These suites exercise omniban against **real** tools, complementing the hermetic
unit tests (which replay golden fixtures). They run a cross-built Linux binary
inside a privileged Linux container so the netfilter calls are real.

```sh
./test/e2e/run.sh                 # debian:bookworm-slim by default
E2E_IMAGE=ubuntu:24.04 ./test/e2e/run.sh
make e2e                          # same, via the Makefile
```

- `netfilter_e2e.sh` — nftables (own table), iptables (own chain), ipset
  (own set + referencing rule), blackhole null-routes, `/etc/hosts` sinkhole
  (create/remove/External detection), lockout guard, dry-run, undo, audit trail.
- `fail2ban_e2e.sh` — a real fail2ban daemon: omniban lists the jail-attributed
  ban, finds it via `check`, and unbans it through `fail2ban-client` (routing to
  the IDS rather than deleting the downstream firewall rule).

Requires Docker with privileged containers (for kernel netfilter access). The
IDS daemons that need more setup or systemd (CrowdSec, CSF, APF, denyhosts,
sshguard) are validated by golden-fixture parsers in the unit tests and on the
target-distro VPS.
