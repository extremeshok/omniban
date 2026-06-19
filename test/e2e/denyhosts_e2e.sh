#!/bin/sh
# Live denyhosts e2e: real denyhosts files + omniban daemon-coordinated edits.
set -u
# DenyHosts is deprecated and no longer packaged on modern distros, so we
# exercise omniban against the real DenyHosts file layout it manages —
# /etc/hosts.deny, the work files, and allowed-hosts (the actual on-disk
# contract). Detection keys off /etc/denyhosts.conf.
mkdir -p /var/lib/denyhosts
: > /etc/denyhosts.conf
: > /etc/hosts.deny
echo "  denyhosts file layout prepared (/etc/denyhosts.conf, /var/lib/denyhosts)"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

$OMNI ban 198.51.100.60 --via denyhosts 2>&1 | sed 's/^/  /'
ck "hosts.deny has the entry"        "grep -q 198.51.100.60 /etc/hosts.deny"
ck "work file kept in sync"          "grep -q 198.51.100.60 /var/lib/denyhosts/hosts"
ck "backup created before edit"      "test -f /etc/hosts.deny.omniban.bak"
ck "omniban lists the ban"           "$OMNI list --backend denyhosts --json | grep -q 198.51.100.60"
ck "check finds it"                  "$OMNI check 198.51.100.60 --json | grep -q 198.51.100.60"
$OMNI unban 198.51.100.60 --via denyhosts >/dev/null 2>&1
ck "hosts.deny cleared"              "! grep -q 198.51.100.60 /etc/hosts.deny"
ck "work file cleared"               "! grep -q 198.51.100.60 /var/lib/denyhosts/hosts"

$OMNI allow 198.51.100.61 --via denyhosts >/dev/null 2>&1
ck "allowed-hosts has the entry"     "grep -q 198.51.100.61 /var/lib/denyhosts/allowed-hosts"
$OMNI unallow 198.51.100.61 --via denyhosts >/dev/null 2>&1
ck "allowed-hosts cleared"           "! grep -q 198.51.100.61 /var/lib/denyhosts/allowed-hosts"

echo "RESULT pass=$pass fail=$fail"
