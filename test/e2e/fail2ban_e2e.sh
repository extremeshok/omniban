#!/bin/sh
# Live IDS e2e: real fail2ban daemon (no systemd) + omniban list/check/unban.
set -u
export DEBIAN_FRONTEND=noninteractive
echo "== installing fail2ban + iptables =="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq fail2ban iptables >/dev/null 2>&1
echo "  fail2ban-client=$(command -v fail2ban-client)"

# Minimal active jail (polling backend, dummy log → no auto-bans; we ban manually).
mkdir -p /etc/fail2ban
cat >/etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
backend = polling
logpath = /var/log/fauxsshd.log
EOF
: > /var/log/fauxsshd.log

fail2ban-client start >/dev/null 2>&1
i=0; while [ $i -lt 10 ]; do fail2ban-client status >/dev/null 2>&1 && break; i=$((i+1)); sleep 1; done
fail2ban-client status >/dev/null 2>&1 && echo "  fail2ban server up" || { echo "  fail2ban failed to start"; exit 0; }

fail2ban-client set sshd banip 203.0.113.77 >/dev/null 2>&1
echo "  fail2ban now reports: $(fail2ban-client status sshd | tr '\n' ' ' | sed 's/.*Banned IP list:/banned:/')"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

ck "omniban lists the fail2ban ban (jail-attributed)" "$OMNI list --backend fail2ban --json | grep -q 203.0.113.77"
ck "entry detail is the jail (sshd)"                  "$OMNI list --backend fail2ban --json | grep -q '\"detail\": *\"sshd\"'"
ck "check finds it"                                   "$OMNI check 203.0.113.77 --json | grep -q 203.0.113.77"
$OMNI unban 203.0.113.77 >/dev/null 2>&1
ck "unban routed through fail2ban-client"             "! fail2ban-client status sshd | grep -q 203.0.113.77"

echo "RESULT pass=$pass fail=$fail"
