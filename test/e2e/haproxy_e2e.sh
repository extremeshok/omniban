#!/bin/sh
# Live HAProxy e2e: real haproxy runtime stats socket + omniban map ban/unban.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq haproxy socat >/dev/null 2>&1 || { echo "SKIP: install failed"; exit 0; }

mkdir -p /etc/haproxy /run/haproxy
: > /etc/haproxy/omniban_deny.map
cat >/etc/haproxy/haproxy.cfg <<'EOF'
global
    stats socket /run/haproxy/admin.sock mode 660 level admin
defaults
    mode http
    timeout connect 5s
    timeout client 5s
    timeout server 5s
frontend fe
    bind 127.0.0.1:8080
    http-request deny if { src,map_ip(/etc/haproxy/omniban_deny.map) -m found }
    default_backend be
backend be
    server s1 127.0.0.1:9 disabled
EOF
haproxy -f /etc/haproxy/haproxy.cfg >/tmp/haproxy.log 2>&1 &
ok=0; i=0; while [ "$i" -lt 15 ]; do [ -S /run/haproxy/admin.sock ] && { ok=1; break; }; i=$((i+1)); sleep 1; done
[ "$ok" = 1 ] || { echo "SKIP: haproxy socket not up"; tail -3 /tmp/haproxy.log 2>/dev/null; exit 0; }
echo "  haproxy up; runtime socket ready"

sock() { echo "$1" | socat - UNIX-CONNECT:/run/haproxy/admin.sock; }

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

$OMNI ban 203.0.113.50 --via haproxy 2>&1 | sed 's/^/  /'
ck "deny map has the entry"   "sock 'show map /etc/haproxy/omniban_deny.map' | grep -q 203.0.113.50"
ck "omniban lists the ban"    "$OMNI list --backend haproxy --json | grep -q 203.0.113.50"
ck "check finds it"           "$OMNI check 203.0.113.50 --json | grep -q 203.0.113.50"
$OMNI unban 203.0.113.50 --via haproxy >/dev/null 2>&1
ck "deny map cleared"         "! sock 'show map /etc/haproxy/omniban_deny.map' | grep -q 203.0.113.50"

echo "RESULT pass=$pass fail=$fail"
