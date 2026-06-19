#!/bin/sh
# Live Suricata e2e: real suricatasc dataset commands over the command socket,
# plus ListBans parsing of the dataset save file (pre-seeded with a real entry).
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq ca-certificates >/dev/null 2>&1
# Suricata is not in Debian bookworm main; pull it from bookworm-backports.
echo "deb http://deb.debian.org/debian bookworm-backports main" >/etc/apt/sources.list.d/backports.list
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq -t bookworm-backports suricata >/dev/null 2>&1 ||
  apt-get install -y -qq suricata >/dev/null 2>&1 ||
  { echo "SKIP: suricata install failed (not in repo)"; exit 0; }

mkdir -p /var/lib/suricata/data /var/run/suricata /etc/suricata
# Seed the dataset save file (plain IP per line — Suricata's "ip" dataset format)
# so omniban ListBans has a real file to parse.
printf '198.51.100.7\n' >/var/lib/suricata/data/omniban-deny.lst
cat >/etc/suricata/omniban.yaml <<'EOF'
%YAML 1.1
---
unix-command:
  enabled: yes
  filename: /var/run/suricata/command.socket
datasets:
  omniban-deny:
    type: ip
    state: /var/lib/suricata/data/omniban-deny.lst
EOF
suricata --unix-socket -c /etc/suricata/omniban.yaml >/tmp/suricata.log 2>&1 &
ok=0; i=0; while [ "$i" -lt 30 ]; do [ -S /var/run/suricata/command.socket ] && { ok=1; break; }; i=$((i+1)); sleep 1; done
[ "$ok" = 1 ] || { echo "SKIP: suricata command socket not up"; tail -4 /tmp/suricata.log 2>/dev/null; exit 0; }
echo "  suricata unix-socket up"

lookup() { suricatasc -c "dataset-lookup omniban-deny ip $1" /var/run/suricata/command.socket 2>/dev/null; }

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

ck "omniban lists the seeded dataset entry" "$OMNI list --backend suricata --json | grep -q 198.51.100.7"

$OMNI ban 203.0.113.70 --via suricata 2>&1 | sed 's/^/  /'
# suricatasc dataset-lookup replies {"message":"item found in set","return":"OK"}
# when present and {"message":"item not found in set","return":"NOK"} when absent.
ck "dataset-lookup finds the live ban" "lookup 203.0.113.70 | grep -qi 'item found in set'"
$OMNI unban 203.0.113.70 --via suricata >/dev/null 2>&1
ck "dataset-lookup no longer matches" "lookup 203.0.113.70 | grep -qi 'not found in set'"

echo "RESULT pass=$pass fail=$fail"
