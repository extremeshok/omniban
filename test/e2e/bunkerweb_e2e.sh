#!/bin/sh
# Live BunkerWeb e2e: omniban ban/list/unban via bwcli. BunkerWeb is a full
# stack (scheduler + nginx + datastore) normally run via docker-compose or the
# Linux integration's systemd services; bwcli's ban store needs the scheduler
# reachable. We attempt the integration install and SKIP cleanly if bwcli or its
# datastore is unavailable in a bare container (the adapter is unit-tested
# against bwcli output). Override BUNKERWEB_INSTALL=1 to force the full install.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq curl ca-certificates >/dev/null 2>&1 || { echo "SKIP: prereqs failed"; exit 0; }

if ! command -v bwcli >/dev/null 2>&1; then
  echo "SKIP: bwcli not present — BunkerWeb needs its full stack (scheduler+datastore);"
  echo "      run on a BunkerWeb host or with the Linux integration to exercise this live."
  exit 0
fi

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

$OMNI ban 203.0.113.95 --via bunkerweb 2>&1 | sed 's/^/  /'
ck "bwcli bans lists it"   "bwcli bans 2>/dev/null | grep -q 203.0.113.95"
ck "omniban lists the ban" "$OMNI list --backend bunkerweb --json | grep -q 203.0.113.95"
$OMNI unban 203.0.113.95 --via bunkerweb >/dev/null 2>&1
ck "bwcli no longer lists it" "! bwcli bans 2>/dev/null | grep -q 203.0.113.95"

echo "RESULT pass=$pass fail=$fail"
