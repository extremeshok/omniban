#!/bin/sh
# Live APF e2e: install Advanced Policy Firewall from source + omniban RW.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq wget ca-certificates iptables >/dev/null 2>&1 || { echo "SKIP: prereqs failed"; exit 0; }
cd /usr/src || exit 0
wget -q https://www.rfxn.com/downloads/apf-current.tar.gz || { echo "SKIP: apf download failed"; exit 0; }
tar -xzf apf-current.tar.gz || { echo "SKIP: apf extract failed"; exit 0; }
cd "$(find . -maxdepth 1 -type d -name 'apf-*' | head -1)" 2>/dev/null || { echo "SKIP: apf dir missing"; exit 0; }
sh install.sh >/tmp/apf-install.log 2>&1 || { echo "SKIP: apf install failed"; exit 0; }
[ -x /usr/local/sbin/apf ] || { echo "SKIP: apf binary missing"; exit 0; }
echo "  apf installed"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

$OMNI ban 203.0.113.20 --via apf 2>&1 | sed 's/^/  /'
ck "deny_hosts.rules has the entry" "grep -q 203.0.113.20 /etc/apf/deny_hosts.rules"
ck "omniban lists the apf ban"      "$OMNI list --backend apf --json | grep -q 203.0.113.20"
ck "check finds it"                 "$OMNI check 203.0.113.20 --json | grep -q 203.0.113.20"
$OMNI unban 203.0.113.20 --via apf >/dev/null 2>&1
ck "deny_hosts.rules cleared"       "! grep -q 203.0.113.20 /etc/apf/deny_hosts.rules"

$OMNI allow 203.0.113.21 --via apf >/dev/null 2>&1
ck "allow_hosts.rules has the entry" "grep -q 203.0.113.21 /etc/apf/allow_hosts.rules"

echo "RESULT pass=$pass fail=$fail"
