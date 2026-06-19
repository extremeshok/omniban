#!/bin/sh
# Live UFW e2e: real ufw + omniban ban/list/check/unban/allow/unallow.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq ufw iptables iproute2 >/dev/null 2>&1 || { echo "SKIP: ufw install failed"; exit 0; }
ufw --force enable >/dev/null 2>&1 || true
echo "  $(ufw status 2>/dev/null | head -1)"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

$OMNI ban 198.51.100.50 --via ufw 2>&1 | sed 's/^/  /'
ck "ufw status shows the deny"   "ufw status | grep -q 198.51.100.50"
ck "omniban lists the ufw ban"   "$OMNI list --backend ufw --json | grep -q 198.51.100.50"
ck "check finds it"              "$OMNI check 198.51.100.50 --json | grep -q 198.51.100.50"
$OMNI unban 198.51.100.50 --via ufw >/dev/null 2>&1
ck "ufw deny removed"            "! ufw status | grep -q 198.51.100.50"

$OMNI allow 198.51.100.51 --via ufw 2>&1 | sed 's/^/  /'
ck "omniban lists the ufw allow" "$OMNI list --kind allow --backend ufw --json | grep -q 198.51.100.51"
$OMNI unallow 198.51.100.51 --via ufw >/dev/null 2>&1
ck "ufw allow removed"           "! ufw status | grep -q 198.51.100.51"

echo "RESULT pass=$pass fail=$fail"
