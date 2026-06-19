#!/bin/sh
# Live e2e: exercise omniban against real nftables/iptables/ipset/iproute2/hosts.
set -u
export DEBIAN_FRONTEND=noninteractive
echo "== installing real backends =="
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq nftables iptables ipset iproute2 >/dev/null 2>&1
echo "  nft=$(command -v nft) iptables=$(command -v iptables) ipset=$(command -v ipset) ip=$(command -v ip)"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

echo "== omniban status =="
$OMNI status 2>&1 | sed 's/^/  /'

echo "== nftables (own table inet omniban) =="
$OMNI ban 198.51.100.10 --via nftables 2>&1 | sed 's/^/  /'
ck "nft kernel set holds the ban"     "nft list table inet omniban | grep -q 198.51.100.10"
ck "list --backend nftables shows it" "$OMNI list --backend nftables --json | grep -q 198.51.100.10"
ck "check finds it"                   "$OMNI check 198.51.100.10 --json | grep -q 198.51.100.10"
$OMNI unban 198.51.100.10 --via nftables >/dev/null 2>&1
ck "nft unban cleared it"             "! nft list table inet omniban | grep -q 198.51.100.10"

echo "== ipset (own set + referencing rule) =="
$OMNI ban 198.51.100.20 --via ipset 2>&1 | sed 's/^/  /'
ck "ipset set holds the ban"          "ipset list omniban-deny4 | grep -q 198.51.100.20"
ck "iptables references the set"      "iptables -S | grep -q 'match-set omniban-deny4'"
$OMNI unban 198.51.100.20 --via ipset >/dev/null 2>&1
ck "ipset unban cleared it"           "! ipset list omniban-deny4 | grep -q 198.51.100.20"

echo "== iptables (own chain OMNIBAN_INPUT) =="
$OMNI ban 198.51.100.30 --via iptables 2>&1 | sed 's/^/  /'
ck "OMNIBAN_INPUT has the DROP"       "iptables -S OMNIBAN_INPUT | grep -q 198.51.100.30"
$OMNI unban 198.51.100.30 --via iptables >/dev/null 2>&1
ck "iptables unban cleared it"        "! iptables -S OMNIBAN_INPUT | grep -q 198.51.100.30"

echo "== blackhole null-route =="
$OMNI null-route 203.0.113.0/24 2>&1 | sed 's/^/  /'
ck "kernel blackhole route present"   "ip route show type blackhole | grep -q 203.0.113.0/24"
ck "list shows it (direction both)"   "$OMNI list --json | grep -q 203.0.113.0/24"
$OMNI unban 203.0.113.0/24 --via blackhole >/dev/null 2>&1
ck "blackhole route removed"          "! ip route show type blackhole | grep -q 203.0.113.0/24"

echo "== /etc/hosts sinkhole =="
$OMNI sinkhole ads.evil.example 2>&1 | sed 's/^/  /'
ck "managed block created"            "grep -q 'omniban BEGIN' /etc/hosts"
ck "0.0.0.0 mapping written"          "grep -q '0.0.0.0 ads.evil.example' /etc/hosts"
ck "check finds the domain"           "$OMNI check ads.evil.example --json | grep -qi ads.evil.example"
$OMNI unban ads.evil.example >/dev/null 2>&1
ck "sinkhole removed"                 "! grep -q 'ads.evil.example' /etc/hosts"

echo "== external (user-added) hosts sinkhole detection =="
printf '0.0.0.0 user-added.example\n' >> /etc/hosts
ck "external entry flagged External"  "$OMNI check user-added.example --json | grep -q '\"external\": *true'"
$OMNI unban user-added.example >/dev/null 2>&1
ck "external removed on request"      "! grep -q 'user-added.example' /etc/hosts"

echo "== lockout guard =="
ck "ban loopback refused w/o --force" "! $OMNI ban 127.0.0.1 --via nftables"
ck "ban loopback allowed w/ --force"  "$OMNI ban 127.0.0.1 --via nftables --force"
$OMNI unban 127.0.0.1 --via nftables >/dev/null 2>&1

echo "== dry-run =="
ck "dry-run prints native command"    "$OMNI ban 8.8.8.8 --via nftables --dry-run | grep -q 'add element'"
ck "dry-run made no kernel change"    "! nft list table inet omniban | grep -q '8.8.8.8'"

echo "== undo =="
$OMNI ban 198.51.100.40 --via nftables >/dev/null 2>&1
$OMNI undo >/dev/null 2>&1
ck "undo reversed the last ban"       "! nft list table inet omniban | grep -q 198.51.100.40"

echo "== audit trail =="
ck "audit log has JSON lines"         "test -s /var/log/omniban.log && grep -q '\"action\"' /var/log/omniban.log"

echo "RESULT pass=$pass fail=$fail"
