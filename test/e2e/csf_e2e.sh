#!/bin/sh
# Live CSF e2e: install ConfigServer Firewall from source + omniban RW.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq perl wget ca-certificates libwww-perl libio-socket-ssl-perl iptables >/dev/null 2>&1 \
  || { echo "SKIP: prereqs failed"; exit 0; }
cd /usr/src || exit 0
wget -q https://download.configserver.com/csf.tgz || { echo "SKIP: csf download failed"; exit 0; }
tar -xzf csf.tgz || { echo "SKIP: csf extract failed"; exit 0; }
cd csf || { echo "SKIP: csf dir missing"; exit 0; }
sh install.sh >/tmp/csf-install.log 2>&1 || { echo "SKIP: csf install failed"; tail -2 /tmp/csf-install.log; exit 0; }
[ -x /usr/sbin/csf ] || { echo "SKIP: csf binary missing"; exit 0; }
echo "  csf installed: $(/usr/sbin/csf --version 2>/dev/null | head -1)"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

$OMNI ban 203.0.113.10 --via csf 2>&1 | sed 's/^/  /'
ck "csf.deny has the entry"      "grep -q 203.0.113.10 /etc/csf/csf.deny"
ck "omniban lists the csf ban"   "$OMNI list --backend csf --json | grep -q 203.0.113.10"
ck "check finds it"              "$OMNI check 203.0.113.10 --json | grep -q 203.0.113.10"
$OMNI unban 203.0.113.10 --via csf >/dev/null 2>&1
ck "csf.deny cleared"            "! grep -q 203.0.113.10 /etc/csf/csf.deny"

$OMNI allow 203.0.113.11 --via csf >/dev/null 2>&1
ck "csf.allow has the entry"     "grep -q 203.0.113.11 /etc/csf/csf.allow"
$OMNI unallow 203.0.113.11 --via csf >/dev/null 2>&1
ck "csf.allow cleared"           "! grep -q 203.0.113.11 /etc/csf/csf.allow"

echo "RESULT pass=$pass fail=$fail"
