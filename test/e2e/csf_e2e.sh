#!/bin/sh
# Live CSF e2e: install ConfigServer Firewall from source + omniban RW.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
# cron provides /etc/crontab, which CSF reads on most operations (it manages a
# TESTING auto-disable cron); without it csf dies mid-command in a slim image.
apt-get install -y -qq curl perl ca-certificates libwww-perl libio-socket-ssl-perl iptables cron >/dev/null 2>&1 \
  || { echo "SKIP: prereqs failed"; exit 0; }
cd /usr/src || exit 0
# CSF_TGZ can point at any assembled csf.tgz. The official host
# (download.configserver.com) is unreachable in some sandboxes, so default to an
# assembled release tarball (the real CSF package, not a build-templated tree).
csf_url="${CSF_TGZ:-https://github.com/Aetherinox/csf-firewall/releases/download/15.10/csf-firewall-v15.10.tgz}"
curl -fsSL -o csf.tgz "$csf_url" || { echo "SKIP: csf download failed"; exit 0; }
tar -xzf csf.tgz || { echo "SKIP: csf extract failed"; exit 0; }
cd csf || { echo "SKIP: csf dir missing"; exit 0; }
sh install.sh >/tmp/csf-install.log 2>&1 || { echo "SKIP: csf install failed"; tail -3 /tmp/csf-install.log; exit 0; }
[ -x /usr/sbin/csf ] || { echo "SKIP: csf binary missing"; exit 0; }
# Enable CSF (a real deployment is not in permanent TESTING mode). With the
# firewall started the DENYIN/ALLOWIN chains exist, so -d/-dr/-a/-ar all apply
# cleanly; in TESTING mode the remove commands error on missing chains and
# poison the next csf invocation.
sed -i 's/^TESTING = "1"/TESTING = "0"/' /etc/csf/csf.conf
csf -e >/dev/null 2>&1 || true
echo "  csf installed: $(/usr/sbin/csf -v 2>/dev/null | tr '\n' ' ')"

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
