#!/usr/bin/env bash
# warden-post-install-diag.sh — runs IMMEDIATELY after install-mac.sh.
# Dumps everything we need to identify why TLS may still fail despite
# install reporting success. Output: /tmp/warden-postinstall.txt
#
# Why each section: install-mac.sh's own verification only probes ONE
# host (api.openai.com) via /usr/bin/curl, only inspects the System
# keychain, and only treats specific curl exit codes as "cert error" —
# leaving false-positive paths where install completes but trust is
# actually broken at runtime.

set +e
OUT="${1:-/tmp/warden-postinstall.txt}"
exec > "$OUT" 2>&1

ts() { date +%H:%M:%S; }
hr() { printf '\n══════ %s ══════\n' "$*"; }

hr "1. Install log tail"
tail -50 /tmp/warden-install.log 2>&1

hr "2. System proxy state"
scutil --proxy

hr "3. Login keychain — ALL mitmproxy CAs (install only checks System)"
security find-certificate -a -c mitmproxy -Z ~/Library/Keychains/login.keychain-db 2>&1 \
  | awk '/SHA-1 hash:/ || /SHA-256 hash:/ || /alis/ {print}'

hr "4. System keychain — ALL mitmproxy CAs (count matters)"
sudo security find-certificate -a -c mitmproxy -Z /Library/Keychains/System.keychain 2>&1 \
  | awk '/SHA-1 hash:/ || /SHA-256 hash:/ {print}'
echo "-- count of CAs in System keychain:"
sudo security find-certificate -a -c mitmproxy -Z /Library/Keychains/System.keychain 2>&1 \
  | grep -c 'SHA-1 hash:'

hr "5. SHA-256 fingerprint comparison (must all match)"
echo "-- container (live, what proxy serves):"
docker exec warden-proxy openssl x509 -in /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem \
  -noout -fingerprint -sha256 2>&1
echo "-- system keychain (PEM extract):"
sudo security find-certificate -c mitmproxy -p /Library/Keychains/System.keychain 2>&1 \
  | openssl x509 -noout -fingerprint -sha256 2>&1
echo "-- ~/.config/warden/mitmproxy-ca.pem (disk):"
[ -f ~/.config/warden/mitmproxy-ca.pem ] && \
  openssl x509 -in ~/.config/warden/mitmproxy-ca.pem -noout -fingerprint -sha256 2>&1
echo "-- expected (from saved memory):"
echo "98:61:93:60:01:A6:30:71:08:01:28:20:90:C9:30:2A:58:B7:20:98:F3:81:1C:20:F6:DB:64:AA:25:AD:04:DD"

hr "6. Trust settings export (does trustd actually trust it for SSL?)"
sudo security trust-settings-export -d /tmp/trust-admin.plist 2>&1
[ -f /tmp/trust-admin.plist ] && plutil -p /tmp/trust-admin.plist 2>&1 \
  | grep -B1 -A20 -i 'mitm' | head -60

hr "7. Apple Secure Transport probe via /usr/bin/curl (the canonical test)"
echo "-- [a] api.openai.com — what install verified:"
/usr/bin/curl -v --max-time 8 --proxy http://127.0.0.1:8080 \
  -o /dev/null https://api.openai.com/v1/models 2>&1 | grep -E '^(\*|<|>)' | head -25
echo
echo "-- [b] api.anthropic.com — actual MITM target the user cares about:"
/usr/bin/curl -v --max-time 8 --proxy http://127.0.0.1:8080 \
  -o /dev/null https://api.anthropic.com/v1/models 2>&1 | grep -E '^(\*|<|>)' | head -25
echo
echo "-- [c] claude.ai — browser MITM target:"
/usr/bin/curl -v --max-time 8 --proxy http://127.0.0.1:8080 \
  -o /dev/null https://claude.ai/ 2>&1 | grep -E '^(\*|<|>)' | head -25

hr "8. mitmproxy live event log during the [a]/[b]/[c] probes"
docker exec warden-proxy sh -c 'tail -80 /data/warden-deep-trace.jsonl 2>/dev/null' \
  | grep -E '"ev":"tls_|"ev":"http_connect|"ev":"server_connect' \
  | tail -40

hr "9. Network sanity — host can hit 127.0.0.1:8080?"
nc -z 127.0.0.1 8080 && echo "127.0.0.1:8080 OPEN" || echo "127.0.0.1:8080 CLOSED"

hr "10. ~/.config/warden contents"
ls -la ~/.config/warden/ 2>&1

hr "11. Shell rc warden block sanity"
grep -A8 'warden proxy' ~/.zshrc 2>&1 | head -12

hr "12. Claude Code settings env"
python3 -c "import json,os; d=json.load(open(os.path.expanduser('~/.claude/settings.json'))); print(json.dumps(d.get('env',{}),indent=2))" 2>&1

hr "13. trustd state"
ps -ef | grep -E '\btrustd\b' | grep -v grep
echo "-- pkgutil for trustd? (verify Apple's binary, not replaced):"
codesign -dv /usr/libexec/trustd 2>&1 | head -3

hr "14. Verdict heuristic"
DISK_FP=$(openssl x509 -in ~/.config/warden/mitmproxy-ca.pem -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ': ' | tr 'a-f' 'A-F')
KC_FP=$(sudo security find-certificate -c mitmproxy -p /Library/Keychains/System.keychain 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ': ' | tr 'a-f' 'A-F')
CONT_FP=$(docker exec warden-proxy openssl x509 -in /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ': ' | tr 'a-f' 'A-F')
KC_COUNT=$(sudo security find-certificate -a -c mitmproxy -Z /Library/Keychains/System.keychain 2>&1 | grep -c 'SHA-1 hash:')
LK_COUNT=$(security find-certificate -a -c mitmproxy -Z ~/Library/Keychains/login.keychain-db 2>&1 | grep -c 'SHA-1 hash:')

echo "DISK_FP    = $DISK_FP"
echo "KC_FP      = $KC_FP"
echo "CONT_FP    = $CONT_FP"
echo "Sys-KC count    = $KC_COUNT"
echo "Login-KC count  = $LK_COUNT"
echo
if [ "$DISK_FP" = "$KC_FP" ] && [ "$KC_FP" = "$CONT_FP" ] && [ "$KC_COUNT" = "1" ] && [ "$LK_COUNT" = "0" ]; then
  echo "VERDICT: artifacts consistent — TLS failure (if any) is at trustd/ASTransport layer, NOT keychain content. Try: sudo killall trustd; sleep 3; rerun probe [b]."
elif [ "$KC_COUNT" -gt "1" ] || [ "$LK_COUNT" -gt "0" ]; then
  echo "VERDICT: STALE/DUPLICATE CAs present — install only purged System keychain. Login keychain or duplicate System entries break trust evaluation. Fix: manually delete extras, or extend uninstall to scan login keychain."
elif [ "$DISK_FP" != "$CONT_FP" ]; then
  echo "VERDICT: CA in ~/.config/warden DIFFERS from container's live CA — copy step in install was wrong / volume was recreated. Run install again."
elif [ "$KC_FP" != "$CONT_FP" ]; then
  echo "VERDICT: System keychain CA DIFFERS from container's live CA — install added the wrong CA. Likely a stale ./mitmproxy-ca.pem leaked into install."
else
  echo "VERDICT: unexpected mismatch combo — inspect raw FPs above."
fi