#!/bin/sh
# Live Shorewall e2e: real shorewall dynamic blacklist (drop/allow/show dynamic).
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq shorewall iptables iproute2 >/dev/null 2>&1 || { echo "SKIP: install failed"; exit 0; }
[ -d /etc/shorewall ] || { echo "SKIP: /etc/shorewall missing"; exit 0; }

iface="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
[ -n "$iface" ] || iface=eth0
cd /etc/shorewall || exit 0
sed -i 's/^STARTUP_ENABLED=No/STARTUP_ENABLED=Yes/' shorewall.conf 2>/dev/null || true
printf 'fw\tfirewall\nnet\tipv4\n' > zones
printf 'net\t%s\t-\n' "$iface" > interfaces
printf '$FW\tnet\tACCEPT\nnet\t$FW\tACCEPT\nnet\tall\tACCEPT\nall\tall\tACCEPT\n' > policy
: > rules
shorewall start >/tmp/sw.log 2>&1 || { echo "SKIP: shorewall start failed"; tail -4 /tmp/sw.log 2>/dev/null; exit 0; }
# "shorewall show dynamic" reads LOGFILE; ensure it exists (no syslog in a slim image).
mkdir -p /var/log; touch /var/log/messages
echo "  shorewall started on $iface"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

$OMNI ban 203.0.113.80 --via shorewall 2>&1 | sed 's/^/  /'
ck "show dynamic has the entry" "shorewall show dynamic 2>/dev/null | grep -q 203.0.113.80"
ck "omniban lists the ban"      "$OMNI list --backend shorewall --json | grep -q 203.0.113.80"
ck "check finds it"             "$OMNI check 203.0.113.80 --json | grep -q 203.0.113.80"
$OMNI unban 203.0.113.80 --via shorewall >/dev/null 2>&1
ck "dynamic blacklist cleared"  "! shorewall show dynamic 2>/dev/null | grep -q 203.0.113.80"

echo "RESULT pass=$pass fail=$fail"
