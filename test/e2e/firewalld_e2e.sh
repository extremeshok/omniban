#!/bin/sh
# Live firewalld e2e: real firewalld daemon (dbus, no systemd) + omniban RW.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq firewalld dbus iptables iproute2 >/dev/null 2>&1 || { echo "SKIP: firewalld install failed"; exit 0; }

mkdir -p /run/dbus
dbus-daemon --system --fork >/dev/null 2>&1 || service dbus start >/dev/null 2>&1 || true
i=0; while [ "$i" -lt 10 ]; do [ -S /run/dbus/system_bus_socket ] && break; i=$((i+1)); sleep 1; done
# The nftables backend can stall on init inside a container; the iptables
# backend starts reliably (a real host uses firewalld's configured default).
sed -i 's/^FirewallBackend=.*/FirewallBackend=iptables/' /etc/firewalld/firewalld.conf 2>/dev/null || true
firewalld --nofork >/tmp/firewalld.log 2>&1 &
ok=0; i=0; while [ "$i" -lt 30 ]; do firewall-cmd --state 2>/dev/null | grep -q running && { ok=1; break; }; i=$((i+1)); sleep 1; done
[ "$ok" = 1 ] || { echo "SKIP: firewalld did not start"; tail -3 /tmp/firewalld.log 2>/dev/null; exit 0; }
echo "  firewalld $(firewall-cmd --version 2>/dev/null), state=$(firewall-cmd --state 2>/dev/null)"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

$OMNI ban 198.51.100.70 --via firewalld 2>&1 | sed 's/^/  /'
ck "rich rule present"             "firewall-cmd --list-rich-rules | grep -q 198.51.100.70"
ck "omniban lists the firewalld ban" "$OMNI list --backend firewalld --json | grep -q 198.51.100.70"
ck "check finds it"                "$OMNI check 198.51.100.70 --json | grep -q 198.51.100.70"
$OMNI unban 198.51.100.70 --via firewalld >/dev/null 2>&1
ck "rich rule removed"             "! firewall-cmd --list-rich-rules | grep -q 198.51.100.70"

$OMNI allow 198.51.100.71 --via firewalld >/dev/null 2>&1
ck "allow rich rule listed"        "$OMNI list --kind allow --backend firewalld --json | grep -q 198.51.100.71"
$OMNI unallow 198.51.100.71 --via firewalld >/dev/null 2>&1
ck "allow rich rule removed"       "! firewall-cmd --list-rich-rules | grep -q 198.51.100.71"

echo "RESULT pass=$pass fail=$fail"
