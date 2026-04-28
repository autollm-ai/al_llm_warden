#!/usr/bin/env bash
# Reverts what install-mac.sh did:
#   1. Disables the macOS system HTTP+HTTPS proxy
#   2. Removes the warden / mitmproxy CA from the System keychain
#   3. Optionally deletes the local CA file
#
# Safe to run multiple times. Does not stop the docker stack.

set -euo pipefail

CA_FILE="${CA_FILE:-./mitmproxy-ca.pem}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C1='\033[1;35m'; OK='\033[32m✔\033[0m'; WARN='\033[33m!\033[0m'; END='\033[0m'
else
  C1=''; OK='[ok]'; WARN='[warn]'; END=''
fi
step() { printf "${C1}▶${END} %s\n" "$*"; }
ok()   { printf "  %b %s\n" "$OK"   "$*"; }
warn() { printf "  %b %s\n" "$WARN" "$*"; }

# ── Detect active service ──────────────────────────────────────────────────
SERVICE=""
while IFS= read -r svc; do
  [ -z "$svc" ] && continue
  if networksetup -getinfo "$svc" 2>/dev/null | grep -qE "^IP address: [0-9]"; then
    SERVICE="$svc"; break
  fi
done < <(networksetup -listallnetworkservices | tail -n +2)

if [ -n "$SERVICE" ]; then
  step "Disabling system proxy on '$SERVICE'"
  sudo networksetup -setwebproxystate       "$SERVICE" off || true
  sudo networksetup -setsecurewebproxystate "$SERVICE" off || true
  ok "System proxy off"
else
  warn "No active network service found — skipping proxy-off step."
fi

# ── Remove CA(s) ──────────────────────────────────────────────────────────
step "Removing mitmproxy CA(s) from System keychain"
removed=0
# Match by Common Name == 'mitmproxy'.  We loop in case multiple installs
# have stacked up.
while sudo security find-certificate -c "mitmproxy" -Z /Library/Keychains/System.keychain >/dev/null 2>&1; do
  SHA=$(sudo security find-certificate -c "mitmproxy" -Z /Library/Keychains/System.keychain \
        | awk -F: '/SHA-1 hash:/{print $2}' | tr -d ' ')
  [ -z "$SHA" ] && break
  sudo security delete-certificate -Z "$SHA" /Library/Keychains/System.keychain || break
  removed=$((removed + 1))
done
if [ "$removed" -gt 0 ]; then
  ok "Removed $removed mitmproxy CA(s) from System keychain"
else
  warn "No mitmproxy CA found in System keychain (already clean)."
fi

# ── Optional file cleanup ─────────────────────────────────────────────────
if [ -f "$CA_FILE" ]; then
  step "Deleting $CA_FILE"
  rm -f "$CA_FILE"
  ok "Removed $CA_FILE"
fi

cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  System proxy disabled, CA removed. Browser traffic is no longer
  intercepted. The Docker stack is still running (run
  'docker compose down' to stop it).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
