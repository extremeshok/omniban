#!/bin/sh
# Live Wazuh e2e: drive the real firewall-drop active-response script directly
# (no manager needed) + omniban ban/list/unban. omniban invokes firewall-drop
# with JSON on stdin; the script applies the iptables DROP and logs it.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq curl gnupg ca-certificates iptables lsb-release >/dev/null 2>&1 || { echo "SKIP: prereqs failed"; exit 0; }

curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH 2>/dev/null | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null \
  || { echo "SKIP: wazuh key fetch failed"; exit 0; }
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" >/etc/apt/sources.list.d/wazuh.list
apt-get update -qq >/dev/null 2>&1
# postinst needs systemd; tolerate it — we only need the AR script + iptables.
WAZUH_MANAGER=localhost apt-get install -y -qq wazuh-agent >/dev/null 2>&1 || true
[ -x /var/ossec/active-response/bin/firewall-drop ] || { echo "SKIP: firewall-drop script not installed"; exit 0; }
mkdir -p /var/ossec/logs; : > /var/ossec/logs/active-responses.log
echo "  wazuh firewall-drop present"

OMNI="${OMNI:-/usr/local/bin/omniban}"
pass=0; fail=0
ck() { if eval "$2" >/dev/null 2>&1; then echo "PASS: $1"; pass=$((pass+1)); else echo "FAIL: $1"; fail=$((fail+1)); fi; }

$OMNI ban 203.0.113.60 --via wazuh 2>&1 | sed 's/^/  /'
ck "iptables DROP added by AR"     "iptables -S 2>/dev/null | grep -q 203.0.113.60"
ck "active-responses.log records add" "grep -q 203.0.113.60 /var/ossec/logs/active-responses.log"
ck "omniban lists the ban"         "$OMNI list --backend wazuh --json | grep -q 203.0.113.60"
ck "check finds it"                "$OMNI check 203.0.113.60 --json | grep -q 203.0.113.60"
$OMNI unban 203.0.113.60 --via wazuh >/dev/null 2>&1
ck "iptables DROP removed"         "! iptables -S 2>/dev/null | grep -q 203.0.113.60"

echo "RESULT pass=$pass fail=$fail"
