#!/bin/sh
# Live ModSecurity (OWASP-style) e2e: nginx + ModSecurity v3 with an
# @ipMatchFromFile blocklist rule; omniban manages the blocklist + reloads.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq nginx libnginx-mod-http-modsecurity curl >/dev/null 2>&1 || { echo "SKIP: install failed (no modsecurity nginx module)"; exit 0; }

mkdir -p /etc/modsecurity
: > /etc/modsecurity/omniban-blocklist.txt
cat >/etc/nginx/modsecurity.conf <<'EOF'
SecRuleEngine On
SecRule REMOTE_ADDR "@ipMatchFromFile /etc/modsecurity/omniban-blocklist.txt" "id:1000,phase:1,deny,status:403,msg:'omniban block'"
EOF
cat >/etc/nginx/sites-available/default <<'EOF'
server {
    listen 127.0.0.1:8080;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsecurity.conf;
    location / { return 200 "ok\n"; }
}
EOF
nginx -t >/tmp/nginx.log 2>&1 || { echo "SKIP: nginx/modsecurity config invalid"; tail -5 /tmp/nginx.log 2>/dev/null; exit 0; }
nginx >/tmp/nginx.run 2>&1 &
ok=0; i=0; while [ "$i" -lt 10 ]; do [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ 2>/dev/null)" = 200 ] && { ok=1; break; }; i=$((i+1)); sleep 1; done
[ "$ok" = 1 ] || { echo "SKIP: nginx not serving"; exit 0; }
echo "  nginx + modsecurity serving"

code() { curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ 2>/dev/null; }

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

$OMNI ban 203.0.113.90 --via modsecurity 2>&1 | sed 's/^/  /'
ck "blocklist has the entry" "grep -q 203.0.113.90 /etc/modsecurity/omniban-blocklist.txt"
ck "omniban lists the ban"   "$OMNI list --backend modsecurity --json | grep -q 203.0.113.90"
ck "blocklist backup made"   "test -f /etc/modsecurity/omniban-blocklist.txt.omniban.bak"

# Enforcement: block this client (loopback needs --force past the lockout guard).
# nginx -s reload is graceful, so poll briefly for new workers to apply the rule.
waitcode() { c=0; i=0; while [ "$i" -lt 6 ]; do [ "$(code)" = "$1" ] && { c=1; break; }; i=$((i+1)); sleep 1; done; [ "$c" = 1 ]; }
$OMNI ban 127.0.0.1 --via modsecurity --force >/dev/null 2>&1
ck "blocked client gets 403"   "waitcode 403"
$OMNI unban 127.0.0.1 --via modsecurity --force >/dev/null 2>&1
ck "unblocked client gets 200" "waitcode 200"

$OMNI unban 203.0.113.90 --via modsecurity >/dev/null 2>&1
ck "blocklist cleared" "! grep -q 203.0.113.90 /etc/modsecurity/omniban-blocklist.txt"

echo "RESULT pass=$pass fail=$fail"
