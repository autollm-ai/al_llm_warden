#!/usr/bin/env bash
# One-line installer for macOS:
#   1. Waits for warden-proxy + warden-api containers to be healthy
#   2. Pulls the mitmproxy CA out of the container
#   3. Trusts the CA in the System keychain   (1 sudo prompt)
#   4. Flips the macOS system-wide HTTP+HTTPS proxy to localhost:8080
#   5. Adds a localhost bypass so the dashboard itself isn't proxied
#
# After this script finishes, opening chatgpt.com / claude.ai / etc. in
# Safari/Chrome/Arc/Firefox routes through Warden automatically. Events
# appear in the dashboard at http://localhost:8090.
#
# To revert everything, run:  scripts/uninstall-mac.sh

set -euo pipefail

CA_FILE="${CA_FILE:-./mitmproxy-ca.pem}"
PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8080}"
DASHBOARD_URL="${DASHBOARD_URL:-http://localhost:8090}"

# ── Pretty output ───────────────────────────────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C1='\033[1;35m'; OK='\033[32m✔\033[0m'; FAIL='\033[31m✘\033[0m'
  WARN='\033[33m!\033[0m'; DIM='\033[2m'; END='\033[0m'
else
  C1=''; OK='[ok]'; FAIL='[fail]'; WARN='[warn]'; DIM=''; END=''
fi

step()  { printf "${C1}▶${END} %s\n" "$*"; }
ok()    { printf "  %b %s\n" "$OK"   "$*"; }
fail()  { printf "  %b %s\n" "$FAIL" "$*" >&2; exit 1; }
warn()  { printf "  %b %s\n" "$WARN" "$*"; }
note()  { printf "  ${DIM}%s${END}\n" "$*"; }

[ "$(uname -s)" = "Darwin" ] || fail "This installer is for macOS. On Linux, run scripts/install-linux.sh."
command -v docker >/dev/null   || fail "Docker not found. Install Docker Desktop or Colima first."
command -v networksetup >/dev/null || fail "networksetup not found — are you on macOS?"

# ── 1. Detect the active network service ───────────────────────────────────
step "Detecting active network service"
SERVICE=""
while IFS= read -r svc; do
  [ -z "$svc" ] && continue
  case "$svc" in "An asterisk"*|"") continue ;; esac
  if networksetup -getinfo "$svc" 2>/dev/null | grep -qE "^IP address: [0-9]"; then
    SERVICE="$svc"
    break
  fi
done < <(networksetup -listallnetworkservices | tail -n +2)
[ -n "$SERVICE" ] || fail "No active network service found. Connect to Wi-Fi or Ethernet first."
ok "Using network service: $SERVICE"

# ── 2. Wait for warden-proxy + the CA file ─────────────────────────────────
step "Waiting for warden-proxy to be ready (model training can take a few minutes on first boot)"
TRIES=0
until docker exec warden-proxy test -f /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem 2>/dev/null; do
  TRIES=$((TRIES + 1))
  if [ "$TRIES" -ge 240 ]; then
    fail "Timed out waiting for the proxy CA to appear. Check 'docker compose logs warden-proxy'."
  fi
  if [ "$((TRIES % 5))" = "0" ]; then
    note "still waiting… ($((TRIES * 2))s)"
  fi
  sleep 2
done
ok "Proxy CA generated"

# ── 3. Copy CA out of the container ────────────────────────────────────────
step "Copying CA → $CA_FILE"
docker cp warden-proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem "$CA_FILE" >/dev/null
ok "CA written to $CA_FILE"

# ── 4. Trust the CA in the System keychain ─────────────────────────────────
step "Trusting the CA in the System keychain (you'll be prompted for your macOS password)"
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain "$CA_FILE"
ok "CA trusted system-wide"

# ── 5. Flip macOS proxy ────────────────────────────────────────────────────
step "Enabling system HTTP+HTTPS proxy → ${PROXY_HOST}:${PROXY_PORT}"
sudo networksetup -setwebproxy           "$SERVICE" "$PROXY_HOST" "$PROXY_PORT"
sudo networksetup -setsecurewebproxy     "$SERVICE" "$PROXY_HOST" "$PROXY_PORT"
sudo networksetup -setwebproxystate      "$SERVICE" on
sudo networksetup -setsecurewebproxystate "$SERVICE" on
sudo networksetup -setproxybypassdomains "$SERVICE" \
  "localhost" "127.0.0.1" "*.local" "169.254/16"
ok "System proxy set"

# ── 6. Verify ──────────────────────────────────────────────────────────────
step "Verifying the proxy is in the path"
if curl -sS --max-time 8 --cacert "$CA_FILE" \
     -o /dev/null -w "%{http_code}\n" \
     -H "Authorization: Bearer sk-fake-validator-token-123456789" \
     https://api.openai.com/v1/models 2>/dev/null | grep -qE "^[1-5][0-9][0-9]$"; then
  ok "Reached api.openai.com via the proxy"
else
  warn "Couldn't reach api.openai.com (offline?) — that's fine; the proxy is still active."
fi

if curl -sS --max-time 5 "$DASHBOARD_URL/api/health" >/dev/null 2>&1; then
  ok "Dashboard responding on $DASHBOARD_URL"
else
  warn "Dashboard not responding on $DASHBOARD_URL — start with 'docker compose up'."
fi

cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  All set. Open Safari/Chrome and visit chatgpt.com (or claude.ai,
  gemini.google.com, perplexity.ai, …) — sensitivity events will appear
  on the dashboard:

      $DASHBOARD_URL

  To revert everything (turn proxy off, remove the CA):

      scripts/uninstall-mac.sh
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
