#!/bin/sh
# Live sshguard e2e: real whitelist file + the nftables set sshguard creates.
# sshguard auto-bans from log analysis (impractical to trigger here), so the
# ban path is exercised against a real sshguard-shaped nft table/set — exactly
# what the daemon maintains — while the allowlist path uses the real file.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq sshguard nftables >/dev/null 2>&1 || { echo "SKIP: sshguard install failed"; exit 0; }
mkdir -p /etc/sshguard
: > /etc/sshguard/whitelist

# Recreate the table/set sshguard uses for blocked attackers.
nft add table ip sshguard 2>/dev/null
nft "add set ip sshguard attackers { type ipv4_addr; }" 2>/dev/null
nft add element ip sshguard attackers { 9.9.9.9 } 2>/dev/null
echo "  sshguard nft set seeded with 9.9.9.9"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

ck "omniban lists the sshguard nft ban" "$OMNI list --backend sshguard --json | grep -q 9.9.9.9"
ck "check finds it"                     "$OMNI check 9.9.9.9 --json | grep -q 9.9.9.9"
$OMNI unban 9.9.9.9 --via sshguard >/dev/null 2>&1
ck "nft set element removed"            "! nft list table ip sshguard | grep -q 9.9.9.9"

$OMNI allow 10.20.30.40 --via sshguard >/dev/null 2>&1
ck "whitelist file has the entry"       "grep -q 10.20.30.40 /etc/sshguard/whitelist"
ck "omniban lists the whitelist allow"  "$OMNI list --kind allow --backend sshguard --json | grep -q 10.20.30.40"
$OMNI unallow 10.20.30.40 --via sshguard >/dev/null 2>&1
ck "whitelist entry removed"            "! grep -q 10.20.30.40 /etc/sshguard/whitelist"

echo "RESULT pass=$pass fail=$fail"
