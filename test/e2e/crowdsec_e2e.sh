#!/bin/sh
# Live CrowdSec e2e: real cscli + Local API + omniban list/check/ban/unban.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq curl gnupg ca-certificates >/dev/null 2>&1 || { echo "SKIP: prereqs failed"; exit 0; }
curl -s https://install.crowdsec.net | bash >/dev/null 2>&1 || { echo "SKIP: crowdsec repo setup failed"; exit 0; }
# The .deb postinst calls systemctl, which fails without systemd — but the
# package files, config, and local machine credentials are created regardless,
# so tolerate a non-zero install and verify cscli directly.
apt-get install -y -qq crowdsec >/dev/null 2>&1 || true
command -v cscli >/dev/null 2>&1 || { echo "SKIP: cscli not installed"; exit 0; }

# Start the agent + Local API as a process (no systemd); wait for LAPI.
crowdsec >/tmp/crowdsec.log 2>&1 &
ok=0; i=0; while [ "$i" -lt 25 ]; do cscli lapi status >/dev/null 2>&1 && { ok=1; break; }; i=$((i+1)); sleep 1; done
[ "$ok" = 1 ] || { echo "SKIP: crowdsec LAPI did not come up"; exit 0; }
echo "  crowdsec LAPI up ($(cscli version 2>/dev/null | head -1))"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

# A decision created by CrowdSec itself (here, cscli) — omniban must see it.
cscli decisions add --ip 203.0.113.88 --duration 4h --type ban >/dev/null 2>&1
ck "omniban lists the crowdsec decision" "$OMNI list --backend crowdsec --json | grep -q 203.0.113.88"
ck "check finds it"                       "$OMNI check 203.0.113.88 --json | grep -q 203.0.113.88"
$OMNI unban 203.0.113.88 --via crowdsec >/dev/null 2>&1
ck "unban deleted the decision"           "! cscli decisions list -o json | grep -q 203.0.113.88"

# A decision created by omniban via cscli.
$OMNI ban 203.0.113.99 --via crowdsec --duration 1h >/dev/null 2>&1
ck "omniban ban created a decision"       "cscli decisions list -o json | grep -q 203.0.113.99"
$OMNI unban 203.0.113.99 --via crowdsec >/dev/null 2>&1
ck "omniban unban removed it"             "! cscli decisions list -o json | grep -q 203.0.113.99"

echo "RESULT pass=$pass fail=$fail"
