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
CA_NICKNAME="warden-mitmproxy"

# ── Brand logo (printed before any other output for instant recall) ────────
print_logo() {
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    # Purple gradient sampled from the AutoLLM mark (#C8B3FE → #421C99).
    local L1='\033[38;5;183m' L2='\033[38;5;141m' L3='\033[38;5;99m'
    local L4='\033[38;5;92m'  L5='\033[38;5;55m'
    local LB='\033[1m' LD='\033[2m' LE='\033[0m'
    printf '\n'
    printf "  ${LB}${L3}▄▀█ █░█ ▀█▀ █▀█    █░░ █░░ █▀▄▀█${LE}\n"
    printf "  ${LB}${L4}█▀█ █▄█ ░█░ █▄█    █▄▄ █▄▄ █░▀░█${LE}\n"
    printf "  ${L2}          ◆ ${LB}${L5}W A R D E N${LE}${L2} ◆${LE}\n"
    printf "  ${LD}${L5}    prompt-flow firewall for LLMs${LE}\n"
    printf '\n'
  else
    printf '\n  AUTO LLM  ◆  WARDEN\n  prompt-flow firewall for LLMs\n\n'
  fi
}
print_logo

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
command -v networksetup >/dev/null || fail "networksetup not found — are you on macOS?"

# ── Docker: auto-install + auto-start if missing ───────────────────────────
# Strategy:
#   1. If `docker` CLI is missing → install Colima via Homebrew (Desktop has
#      a license-acceptance click we can't automate).
#   2. If `docker info` already works → done.
#   3. Else try, in order, every runtime that's actually installed —
#        a. Docker Desktop (open the .app)
#        b. Colima (`colima start`)
#      then poll for `docker info` for up to 90s.
#   4. If neither is installed, fall through to step 1 (install Colima).
wait_for_daemon() {
  local tries=0
  until docker info >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -ge 45 ]; then
      return 1
    fi
    if [ "$((tries % 5))" = "0" ]; then
      note "still waiting for Docker daemon… ($((tries * 2))s)"
    fi
    sleep 2
  done
  return 0
}

start_docker_desktop() {
  if [ -d "/Applications/Docker.app" ] || [ -d "$HOME/Applications/Docker.app" ]; then
    step "Starting Docker Desktop"
    open -ga Docker || return 1
    return 0
  fi
  return 1
}

start_colima() {
  if command -v colima >/dev/null; then
    step "Starting Colima (spins up a small Linux VM — first start can take ~1 min)"
    colima start || return 1
    return 0
  fi
  return 1
}

install_docker() {
  step "Docker not found on host — installing Colima + Docker CLI via Homebrew"
  if ! command -v brew >/dev/null; then
    fail "Homebrew not found. Install it from https://brew.sh, then re-run this installer.
       Alternatively, install Docker Desktop from https://www.docker.com/products/docker-desktop/ and re-run."
  fi
  brew install colima docker docker-compose
  start_colima || fail "colima failed to start. Try 'colima start --verbose' to see why."
  command -v docker >/dev/null || fail "Docker install reported success but 'docker' is still missing."
  ok "Docker installed (Colima backend)"
}

if ! command -v docker >/dev/null; then
  install_docker
fi

if ! docker info >/dev/null 2>&1; then
  # CLI present but daemon down. Try to start whichever runtime is installed.
  started=0
  if start_docker_desktop; then started=1
  elif start_colima;        then started=1
  fi
  if [ "$started" = "0" ]; then
    # Nothing installed that we can start — install Colima ourselves.
    install_docker
  fi
  step "Waiting for Docker daemon to come up"
  if ! wait_for_daemon; then
    fail "Docker daemon didn't come up within 90s. Open Docker Desktop manually (or run 'colima start --verbose'), then re-run this installer."
  fi
  ok "Docker daemon ready"
fi

# ── Bring up the warden stack if not already running ───────────────────────
# Without this, the script proceeds to wait for warden-proxy's CA file and
# times out — the containers were never started.
#
# Two gotchas we've hit on macOS:
#   1. If a previous Warden install set HTTP_PROXY=http://127.0.0.1:8080
#      in the shell, those env vars leak into `docker compose` and confuse
#      BuildKit / Docker Desktop's network. Strip them for the duration.
#      127.0.0.1 means "the proxy" from the host's view but means nothing
#      from inside the build VM, so registry pulls fail with weird DNS /
#      "no HTTPS proxy" errors.
#   2. Docker Desktop reports "ready" before its VM's DNS is fully wired.
#      Fresh-start pulls then fail with `lookup registry-1.docker.io: no
#      such host`. Retry once after a short wait.
docker_proxyless() {
  env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
      -u http_proxy -u https_proxy -u all_proxy \
      docker "$@"
}
docker_compose_proxyless() {
  if docker compose version >/dev/null 2>&1; then
    env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
        -u http_proxy -u https_proxy -u all_proxy \
        docker compose "$@"
  elif command -v docker-compose >/dev/null; then
    env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
        -u http_proxy -u https_proxy -u all_proxy \
        docker-compose "$@"
  else
    return 127
  fi
}

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'warden-proxy'; then
  COMPOSE_FILE="$(cd "$(dirname "$0")/.." && pwd)/docker-compose.yml"
  if [ ! -f "$COMPOSE_FILE" ]; then
    fail "docker-compose.yml not found at $COMPOSE_FILE — run this script from the repo."
  fi

  # Pre-pull the base image so DNS / registry issues surface before the
  # build does, with a clearer error than a 30-line BuildKit dump.
  step "Pulling python:3.11-slim base image (lets BuildKit reuse it)"
  if ! docker_proxyless pull python:3.11-slim >/dev/null 2>&1; then
    note "First pull failed — waiting 10s for Docker's network and retrying once"
    sleep 10
    if ! docker_proxyless pull python:3.11-slim; then
      fail "Couldn't pull python:3.11-slim from Docker Hub.
       Likely cause: Docker Desktop's VM has no DNS yet, or a prior HTTP_PROXY
       env var leaked into Docker. Try:
         • Quit Docker Desktop, reopen it, wait until the whale is steady, re-run.
         • Or: open new shell (so HTTP_PROXY isn't set) and re-run."
    fi
  fi
  ok "Base image present"

  step "Starting warden-proxy + warden-api (docker compose up -d --build)"
  if ! docker_compose_proxyless -f "$COMPOSE_FILE" up -d --build; then
    note "First compose run failed — waiting 10s and retrying once"
    sleep 10
    docker_compose_proxyless -f "$COMPOSE_FILE" up -d --build \
      || fail "'docker compose up -d' failed. Run it manually with -f $COMPOSE_FILE to see full output."
  fi
  ok "Containers launched"
fi

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

# Self-heal: a stale ./mitmproxy-ca.pem from a prior install where the
# warden-mitm volume has since been recreated will trust the WRONG CA into
# the keychain. Always start from a clean slate when CA_FILE is the default
# path. (Refuse to clobber a non-default path the user explicitly set.)
if [ "$CA_FILE" = "./mitmproxy-ca.pem" ] && [ -e "$CA_FILE" ] && [ ! -w "$CA_FILE" ]; then
  step "Cleaning up stale root-owned $CA_FILE from a prior run"
  sudo rm -f "$CA_FILE"
fi

# ── 3. Copy CA out of the container ────────────────────────────────────────
# Tried-and-failed methods we've seen on macOS:
#   * 'docker cp file' under Docker Desktop / Colima can report success but
#     write nothing useful into the host path when the runtime VM has its
#     own filesystem confinement. Same class of bug as snap-Docker on Linux.
#   * Plain 'docker exec cat > file' under those runtimes can exit 0 with
#     no bytes on stdout.
# What works EVERYWHERE: fetch the CA from mitmproxy's own self-served
# endpoint (http://mitm.it/cert/pem) via the proxy. No docker access needed
# at all, and this is the documented retrieval method per the mitmproxy docs.
# Always validate as a real PEM before we hand it to `security
# add-trusted-cert` — trusting a 0-byte file silently breaks every site.
step "Copying CA → $CA_FILE"
CA_PATH_IN_CTR="/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"
TMP_CA="$(mktemp -t warden-ca)"

is_valid_pem() {
  [ -s "$1" ] && grep -q 'BEGIN CERTIFICATE' "$1"
}

copy_method=""

# Method 1 (preferred): fetch via the proxy's mitm.it endpoint. Bypasses
# docker entirely and proves the proxy is reachable on the host.
if [ -z "$copy_method" ]; then
  : > "$TMP_CA"
  if curl -sSf --max-time 10 -x "http://${PROXY_HOST}:${PROXY_PORT}" \
       http://mitm.it/cert/pem -o "$TMP_CA" 2>/dev/null && is_valid_pem "$TMP_CA"; then
    copy_method="mitm.it/cert/pem (via proxy)"
  fi
fi

# Method 2: docker exec ... cat. Cheap to try.
if [ -z "$copy_method" ]; then
  : > "$TMP_CA"
  if docker exec warden-proxy cat "$CA_PATH_IN_CTR" > "$TMP_CA" 2>/dev/null && is_valid_pem "$TMP_CA"; then
    copy_method="docker exec cat"
  fi
fi

# Method 3: 'docker cp container:path -' tar-streamed to stdout.
if [ -z "$copy_method" ] && command -v tar >/dev/null; then
  : > "$TMP_CA"
  if docker cp "warden-proxy:$CA_PATH_IN_CTR" - 2>/dev/null | tar -xO 2>/dev/null > "$TMP_CA" && is_valid_pem "$TMP_CA"; then
    copy_method="docker cp tar-stream"
  fi
fi

# Method 4: read straight from the named volume's mountpoint on the host
# (works under Colima where the VM's filesystem is bind-mounted to the host).
if [ -z "$copy_method" ]; then
  : > "$TMP_CA"
  for vol in al_llm_warden_warden-mitm warden-mitm; do
    mp="$(docker volume inspect "$vol" --format '{{.Mountpoint}}' 2>/dev/null)"
    [ -z "$mp" ] && continue
    if sudo test -f "$mp/mitmproxy-ca-cert.pem" 2>/dev/null && \
       sudo cat "$mp/mitmproxy-ca-cert.pem" > "$TMP_CA" 2>/dev/null && \
       is_valid_pem "$TMP_CA"; then
      copy_method="volume mountpoint ($mp)"
      break
    fi
  done
fi

if [ -z "$copy_method" ]; then
  rm -f "$TMP_CA"
  echo ""
  echo "  Diagnostic — what's in the container:"
  docker exec warden-proxy ls -la /home/mitmproxy/.mitmproxy/ 2>&1 || true
  echo ""
  fail "All four CA-fetch methods failed. Make sure 'docker compose up' shows warden-proxy as healthy on port 8080."
fi

ok "Fetched via: $copy_method"
mv -f "$TMP_CA" "$CA_FILE"
if ! is_valid_pem "$CA_FILE"; then
  fail "$CA_FILE is empty or not a PEM after copy. Aborting before we trust garbage."
fi
ok "CA written to $CA_FILE ($(wc -c < "$CA_FILE" | tr -d ' ') bytes)"

# ── 4. Trust the CA in the System keychain ─────────────────────────────────
# Drop any previously-trusted mitmproxy CA from prior installs first — if
# the warden-mitm volume was recreated, the in-container CA now has a
# different fingerprint and the stale keychain entry will keep failing
# verification even after this fresh install.
step "Removing any stale mitmproxy CA(s) from System keychain (so a recreated volume doesn't leave a stale trust)"
while sudo security find-certificate -c "mitmproxy" -Z /Library/Keychains/System.keychain >/dev/null 2>&1; do
  STALE_SHA=$(sudo security find-certificate -c "mitmproxy" -Z /Library/Keychains/System.keychain \
              | awk -F: '/SHA-1 hash:/{print $2}' | tr -d ' ')
  [ -z "$STALE_SHA" ] && break
  sudo security delete-certificate -Z "$STALE_SHA" /Library/Keychains/System.keychain >/dev/null 2>&1 || break
done
ok "System keychain clear of old mitmproxy CAs"

step "Trusting the CA in the System keychain (you'll be prompted for your macOS password)"
# -p ssl -p basic: explicitly trust for SSL + basic policies. Without
# explicit policies, Chrome's verifier on recent macOS (Chrome Root Store
# rollout) sometimes rejects locally-installed roots that lack an SSL
# trust setting. Belt-and-suspenders.
sudo security add-trusted-cert -d -r trustRoot -p ssl -p basic \
  -k /Library/Keychains/System.keychain "$CA_FILE"
ok "CA trusted system-wide"

# CRITICAL FIX (macOS Sequoia 15.x and later):
#   `add-trusted-cert` updates the on-disk admin trust DB at
#   /Library/Security/Trust Settings/Admin.plist, but the running `trustd`
#   daemon caches trust decisions in-process and does NOT re-read the DB
#   automatically. Until trustd reloads, every TLS handshake — including
#   Chrome/Safari/Arc/Edge URL loads and curl --proxy connections — calls
#   into the cached "not trusted" answer for our brand-new CA. Symptom:
#   the (i) icon in the address bar says "Your connection is not secure"
#   on every LLM site even though the cert IS now in the keychain and
#   marked trusted. Before adding this flush, the verify step at the end
#   could pass (it reads disk via openssl x509) while browsers still fail
#   (they read trustd via SecTrustEvaluate). SIGHUP makes trustd reload
#   without dropping in-flight evaluations; if launchd respawns, the new
#   instance reads fresh state too. macOS-only — Linux has no equivalent.
step "Refreshing macOS trust daemon so browsers see the new trust"
sudo killall -HUP trustd 2>/dev/null || true
# trustd reloads its DB asynchronously after HUP — give it a beat to settle
# before we hand off to the verification step that depends on it.
sleep 1
ok "Trust daemon (trustd) refreshed"

# ── 4b. Verify browser trust BEFORE we flip the system proxy ───────────────
#   ORDERING IS LOAD-BEARING. If trust is broken, the *next* sections enable
#   the system HTTP+HTTPS proxy and write HTTP_PROXY into ~/.zshrc. Doing
#   that with broken trust leaves the user's machine in a state where every
#   HTTPS request fails, INCLUDING claude-code calls home — they then can't
#   even ask Claude for help debugging. So we probe trust here, while the
#   user's network state is still untouched, and bail out cleanly before
#   touching networksetup if it's wrong.
#   The probe uses /usr/bin/curl (links Apple Secure Transport, reads the
#   System keychain — same trust path Safari/Chrome/Arc/Edge use). Homebrew
#   curl links LibreSSL with /etc/ssl/cert.pem and would silently lie.
#   Note: --proxy is passed explicitly, so this works WITHOUT the system
#   proxy being enabled yet.
step "Verifying browsers will accept the cert (before changing any network settings)"
SYS_CURL="/usr/bin/curl"
verify_browser_trust() {
  local out rc
  out=$("$SYS_CURL" -sS --max-time 8 \
       --proxy "http://${PROXY_HOST}:${PROXY_PORT}" \
       -o /dev/null -w "%{http_code}" \
       -H "Authorization: Bearer sk-fake-validator-token-123456789" \
       https://api.openai.com/v1/models 2>&1)
  rc=$?
  if [ "$rc" = "0" ]; then echo "ok"
  elif printf '%s' "$out" | grep -qiE 'certificate|SSL'; then echo "cert-rejected"
  elif [ "$rc" = "35" ] || [ "$rc" = "51" ] || [ "$rc" = "60" ] \
    || [ "$rc" = "77" ] || [ "$rc" = "83" ]; then echo "cert-rejected"
  else echo "offline"
  fi
}

if [ ! -x "$SYS_CURL" ]; then
  warn "/usr/bin/curl missing — can't verify browser trust path. Continuing anyway."
else
  result=$(verify_browser_trust)
  case "$result" in
    ok)
      ok "TLS chain validates via System keychain — browsers will trust it"
      ;;
    offline)
      warn "Couldn't reach api.openai.com via the proxy (offline?) — skipping browser-trust check.
        If you see 'Not Secure' in the address bar after install, re-run with network access." ;;
    cert-rejected)
      # On-disk trust says yes, but trustd's cached answer says no. SIGHUP
      # didn't stick; force a full restart (launchd respawns within ~50ms).
      warn "Browser-trust path failing despite trust on disk. Forcing a hard trustd restart."
      sudo killall trustd 2>/dev/null || true
      sleep 2
      result2=$(verify_browser_trust)
      if [ "$result2" = "ok" ]; then
        ok "TLS chain validates after trustd restart — browsers will trust it"
      else
        echo ""
        echo "  Diagnostic dump (cert IS in keychain but Apple Secure Transport rejects it):"
        echo "    System keychain mitmproxy cert:"
        sudo security find-certificate -c mitmproxy -Z /Library/Keychains/System.keychain 2>&1 \
          | sed 's/^/      /' | head -8
        echo ""
        # IMPORTANT: do NOT enable the system proxy on this failure path —
        # we haven't touched networksetup yet, so the user's machine is
        # still in its pre-install state. They can keep using claude-code
        # to debug. Tell them how to clean up the trust we DID add.
        fail "System keychain trust isn't being honored by Apple Secure Transport even after a trustd restart.
       Stopping HERE so we don't enable the system proxy on a broken trust path —
       your machine is still in its pre-install state and claude-code still works.
       Recovery: bash scripts/uninstall-mac.sh (removes the trusted CA we just added)
       Then reboot and try again. If it still fails after a reboot, share the
       diagnostic above."
      fi
      ;;
  esac
fi

# ── 5. Flip macOS proxy ────────────────────────────────────────────────────
# SAFETY: snapshot the user's *current* networksetup proxy state to
# ~/.config/warden/state.json BEFORE we flip anything, so the uninstaller
# can restore an original SOCKS / corporate proxy instead of just turning
# all proxies off. We only write the snapshot if one doesn't already
# exist — a re-run mustn't capture warden's own state as the "original".
WARDEN_STATE_DIR="$HOME/.config/warden"
WARDEN_STATE_FILE="$WARDEN_STATE_DIR/state.json"
mkdir -p "$WARDEN_STATE_DIR"
if [ ! -f "$WARDEN_STATE_FILE" ]; then
  step "Snapshotting current macOS proxy state → $WARDEN_STATE_FILE (so uninstall can restore it)"
  # SAFETY: refuse to snapshot a state already pointing at warden — that
  # would freeze warden's own values as the "original" so uninstall could
  # never actually disable the proxy. (Happens on a re-install where a
  # prior run was interrupted before writing the snapshot.)
  python3 - "$WARDEN_STATE_FILE" "$SERVICE" "$PROXY_HOST" "$PROXY_PORT" <<'PY'
import json, subprocess, sys, pathlib
out, service, host, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
def info(cmd):
    try:
        return subprocess.check_output(cmd, text=True)
    except Exception:
        return ""
def parse(text):
    d = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            d[k.strip().lower()] = v.strip()
    return d
web    = parse(info(["networksetup","-getwebproxy",       service]))
secure = parse(info(["networksetup","-getsecurewebproxy", service]))
bypass = info(["networksetup","-getproxybypassdomains", service]).strip().splitlines()
if web.get("enabled") == "Yes" and secure.get("enabled") == "Yes" \
   and web.get("server") == host and secure.get("server") == host \
   and web.get("port") == port and secure.get("port") == port:
    print("WARDEN_PRE_FLIP", file=sys.stderr)
    sys.exit(2)
state = {
  "mac_networksetup": {
    "service":    service,
    "web":        {"enabled": web.get("enabled","No") == "Yes",
                   "server":  web.get("server",""), "port": web.get("port","")},
    "secure_web": {"enabled": secure.get("enabled","No") == "Yes",
                   "server":  secure.get("server",""), "port": secure.get("port","")},
    "bypass":     [b for b in bypass if b and b != "There aren't any bypass domains set on this network service."],
  }
}
pathlib.Path(out).write_text(json.dumps(state, indent=2))
PY
  rc=$?
  if [ "$rc" -eq 0 ]; then
    ok "Snapshot written"
  elif [ "$rc" -eq 2 ]; then
    warn "Skipped snapshot — current networksetup already points at warden (likely a re-install). Uninstall will fall back to proxy-off."
  else
    warn "Snapshot script failed (rc=$rc) — uninstall will fall back to proxy-off."
  fi
else
  note "Existing $WARDEN_STATE_FILE — keeping the original snapshot intact."
fi

step "Enabling system HTTP+HTTPS proxy → ${PROXY_HOST}:${PROXY_PORT}"
sudo networksetup -setwebproxy           "$SERVICE" "$PROXY_HOST" "$PROXY_PORT"
sudo networksetup -setsecurewebproxy     "$SERVICE" "$PROXY_HOST" "$PROXY_PORT"
sudo networksetup -setwebproxystate      "$SERVICE" on
sudo networksetup -setsecurewebproxystate "$SERVICE" on
sudo networksetup -setproxybypassdomains "$SERVICE" \
  "localhost" "127.0.0.1" "*.local" "169.254/16"
ok "System proxy set"

# ─── Terminal-CLI proxy ────────────────────────────────────────────────────
# networksetup only routes apps that read the macOS system proxy (Safari,
# Chrome, Arc, GUI Slack, etc.). Terminal CLIs (curl, python, node,
# claude-code, gh, brew) read HTTP_PROXY/HTTPS_PROXY env vars and would
# otherwise bypass warden entirely. Write the exports to ~/.zshrc (the
# default shell since Catalina) and ~/.bash_profile if present.
# Idempotent: a marker block is replaced on every run.
step "Wiring terminal CLIs through warden (~/.zshrc, ~/.bash_profile)"
WARDEN_RC_BEGIN="# >>> warden proxy >>>"
WARDEN_RC_END="# <<< warden proxy <<<"
# Stable CA path so settings.json / env vars don't break if the user moves
# the repo. ~/.config/warden/mitmproxy-ca.pem is the canonical home.
mkdir -p "$HOME/.config/warden"
cp -f "$CA_FILE" "$HOME/.config/warden/mitmproxy-ca.pem"

# Build a *combined* CA bundle = system roots + mitmproxy CA. SAFETY:
#   REQUESTS_CA_BUNDLE / SSL_CERT_FILE *replace* the trust store for tools
#   that strictly honor them (Python, pip). Pointing them at the bare
#   mitmproxy CA breaks any HTTPS that warden's proxy *passes through*
#   unchanged — including pypi.org — because the leaf cert chains to a
#   public CA that isn't in the bundle. /etc/ssl/cert.pem on macOS is
#   the system root snapshot LibreSSL/OpenSSL ship with; concat with the
#   mitm CA so both pass-through and MITMd HTTPS verify.
COMBINED_BUNDLE="$HOME/.config/warden/warden-ca-bundle.pem"
SYS_BUNDLE=""
for p in /etc/ssl/cert.pem /usr/local/etc/openssl@3/cert.pem /opt/homebrew/etc/openssl@3/cert.pem; do
  [ -f "$p" ] && SYS_BUNDLE="$p" && break
done
if [ -z "$SYS_BUNDLE" ] && command -v security >/dev/null; then
  TMP_SYS="$(mktemp)"
  security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain >"$TMP_SYS" 2>/dev/null && \
    [ -s "$TMP_SYS" ] && SYS_BUNDLE="$TMP_SYS"
fi
if [ -n "$SYS_BUNDLE" ] && [ -s "$SYS_BUNDLE" ]; then
  cat "$SYS_BUNDLE" "$CA_FILE" > "$COMBINED_BUNDLE"
  chmod 0644 "$COMBINED_BUNDLE"
  ok "Combined CA bundle written to $COMBINED_BUNDLE"
  [ "$SYS_BUNDLE" = "${TMP_SYS:-}" ] && rm -f "$TMP_SYS"
else
  warn "No system CA bundle found — falling back to bare mitmproxy CA. Pass-through HTTPS (e.g. pypi) may break for tools that strictly honor REQUESTS_CA_BUNDLE."
  COMBINED_BUNDLE="$HOME/.config/warden/mitmproxy-ca.pem"
fi

# NODE_EXTRA_CA_CERTS: Node ignores SSL_CERT_FILE/REQUESTS_CA_BUNDLE and
# uses its own bundled CA store. Without this var, every Node-based client
# (Claude Code, Cursor, npm, gh-cli on Node, etc.) rejects warden's MITM
# cert during TLS handshake — symptom in mitmproxy.log is a steady drip
# of "Client TLS handshake failed. The client disconnected during the
# handshake. ... this may indicate that the client does not trust the
# proxy's certificate" for api.anthropic.com / claude.ai.
WARDEN_RC_BLOCK="$WARDEN_RC_BEGIN
export HTTP_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
export HTTPS_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
export ALL_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
export NO_PROXY=localhost,127.0.0.1,::1
export REQUESTS_CA_BUNDLE=$COMBINED_BUNDLE
export SSL_CERT_FILE=$COMBINED_BUNDLE
export NODE_EXTRA_CA_CERTS=$COMBINED_BUNDLE
$WARDEN_RC_END"

for rc in "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.bashrc"; do
  [ -f "$rc" ] || continue
  python3 - "$rc" "$WARDEN_RC_BEGIN" "$WARDEN_RC_END" "$WARDEN_RC_BLOCK" <<'PY'
import sys, pathlib, re
rc, begin, end, block = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
p = pathlib.Path(rc)
text = p.read_text()
pattern = re.compile(re.escape(begin) + r"[\s\S]*?" + re.escape(end) + r"\n?", re.MULTILINE)
text = pattern.sub("", text).rstrip() + "\n\n" + block + "\n"
p.write_text(text)
PY
  ok "Patched $rc"
done
note "Open a new terminal (or run 'source ~/.zshrc') for env vars to take effect."

# ── 6. Verify ──────────────────────────────────────────────────────────────
# Browser-trust was already verified BEFORE we touched networksetup
# (see step 4b above) so we don't re-test it here. The remaining checks
# are cosmetic / informational:
#   - chain verifies against on-disk CA via the system proxy (sanity)
#   - dashboard responds on localhost
step "Verifying the proxy chain end-to-end"
if curl -sS --max-time 8 --cacert "$CA_FILE" \
     --proxy "http://${PROXY_HOST}:${PROXY_PORT}" \
     -o /dev/null -w "%{http_code}\n" \
     -H "Authorization: Bearer sk-fake-validator-token-123456789" \
     https://api.openai.com/v1/models 2>/dev/null | grep -qE "^[1-5][0-9][0-9]$"; then
  ok "Reached api.openai.com via the proxy (chain verifies against on-disk CA)"
else
  warn "Couldn't reach api.openai.com via proxy (offline?) — that's fine; the proxy is still active."
fi

if curl -sS --max-time 5 --noproxy '*' "$DASHBOARD_URL/api/health" >/dev/null 2>&1; then
  ok "Dashboard responding on $DASHBOARD_URL"
else
  warn "Dashboard not responding on $DASHBOARD_URL — start with 'docker compose up'."
fi

# ── 7. Optionally wire Claude Code (and other Anthropic clients) ───────────
#       through the proxy by editing ~/.claude/settings.json in place.
configure_claude_code() {
  if ! command -v python3 >/dev/null; then
    warn "python3 not found — can't safely merge ~/.claude/settings.json. Skipping Claude Code config."
    return
  fi
  CA_STABLE="$HOME/.config/warden/mitmproxy-ca.pem"
  CLAUDE_DIR="$HOME/.claude"
  CLAUDE_SETTINGS="$CLAUDE_DIR/settings.json"
  mkdir -p "$CLAUDE_DIR"
  # SAFETY: keep a one-time pristine backup of the user's pre-warden
  # settings. Never overwritten on subsequent runs.
  if [ -f "$CLAUDE_SETTINGS" ] && [ ! -f "$CLAUDE_SETTINGS.warden-pre-patch.bak" ]; then
    cp -f "$CLAUDE_SETTINGS" "$CLAUDE_SETTINGS.warden-pre-patch.bak"
    ok "Backed up original settings to $CLAUDE_SETTINGS.warden-pre-patch.bak"
  fi
  python3 - "$CLAUDE_SETTINGS" "$CA_STABLE" "http://${PROXY_HOST}:${PROXY_PORT}" <<'PY'
import json, sys, pathlib
path, ca, proxy = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
data = {}
if p.exists() and p.stat().st_size > 0:
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError:
        backup = p.with_suffix(p.suffix + ".warden-backup")
        p.replace(backup)
        print(f"  ! existing {path} was not valid JSON — backed up to {backup} and rewriting.")
        data = {}
if not isinstance(data, dict):
    data = {}
env = data.get("env") if isinstance(data.get("env"), dict) else {}
env["HTTPS_PROXY"] = proxy
env["HTTP_PROXY"] = proxy
env["NODE_EXTRA_CA_CERTS"] = ca
data["env"] = env
p.write_text(json.dumps(data, indent=2) + "\n")
PY
  ok "Patched $CLAUDE_SETTINGS (HTTPS_PROXY, HTTP_PROXY, NODE_EXTRA_CA_CERTS merged into env)"
}

case "${WARDEN_CLAUDE_CODE:-}" in
  1|y|yes|true) DO_CLAUDE=1 ;;
  0|n|no|false) DO_CLAUDE=0 ;;
  *)
    if [ -t 0 ]; then
      printf "${C1}▶${END} Also protect Claude Code? (route the Anthropic SDK + claude.ai CLI through Warden) [y/N] "
      read -r ans || ans=""
      case "$ans" in y|Y|yes|YES) DO_CLAUDE=1 ;; *) DO_CLAUDE=0 ;; esac
    else
      DO_CLAUDE=0
      note "Non-interactive run — skipping Claude Code config. Re-run with WARDEN_CLAUDE_CODE=1 to enable."
    fi
    ;;
esac

if [ "$DO_CLAUDE" = "1" ]; then
  step "Configuring Claude Code (~/.claude/settings.json)"
  configure_claude_code
fi

# ── 8. Verify the cert in the System keychain matches what mitmproxy is
#       actually serving. If they disagree (e.g. stale CA from before the
#       warden-mitm volume was recreated), the install "succeeded" but
#       Chrome / Safari will still throw NET::ERR_CERT_AUTHORITY_INVALID
#       and websites won't load. Fail loudly here instead of letting the
#       user discover it in the browser.
step "Verifying System-keychain trust matches the live proxy CA"
DISK_FP="$(openssl x509 -in "$CA_FILE" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ': ' | tr 'a-f' 'A-F')"
KC_FP="$(sudo security find-certificate -c "mitmproxy" -p /Library/Keychains/System.keychain 2>/dev/null \
         | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ': ' | tr 'a-f' 'A-F')"
if [ -n "$DISK_FP" ] && [ -n "$KC_FP" ] && [ "$DISK_FP" = "$KC_FP" ]; then
  ok "Fingerprints match (${DISK_FP:0:23}…)"
elif [ -z "$KC_FP" ]; then
  fail "mitmproxy CA not found in System keychain after install. Browsers will reject the cert. Re-run this installer; if it keeps failing, run 'scripts/uninstall-mac.sh' first."
else
  warn "System-keychain fingerprint differs from disk CA — browsers will still reject. Forcing a re-add."
  while sudo security find-certificate -c "mitmproxy" -Z /Library/Keychains/System.keychain >/dev/null 2>&1; do
    SHA=$(sudo security find-certificate -c "mitmproxy" -Z /Library/Keychains/System.keychain \
          | awk -F: '/SHA-1 hash:/{print $2}' | tr -d ' ')
    [ -z "$SHA" ] && break
    sudo security delete-certificate -Z "$SHA" /Library/Keychains/System.keychain >/dev/null 2>&1 || break
  done
  sudo security add-trusted-cert -d -r trustRoot -p ssl -p basic \
    -k /Library/Keychains/System.keychain "$CA_FILE"
  ok "Re-added; verify with 'security find-certificate -c mitmproxy -p /Library/Keychains/System.keychain'"
fi

# ── 9. Quit browsers so they re-read trust on next launch ──────────────────
# Newly-trusted CAs in the System keychain are picked up by Safari/Chrome
# only on next launch. SAFETY:
#   • Apple Events (osascript) target the actual GUI app — they can never
#     match a CLI tool that has "chrome" in its argv (unlike pkill -f).
#   • The macOS apps themselves prompt about unsaved tabs/forms, but a
#     user with 50 tabs open doesn't want a sudden quit dialog mid-flow.
#     So WE prompt FIRST, listing which browsers are running, and only
#     send the quit if the user confirms.
#   • Skippable in non-interactive runs via WARDEN_QUIT_BROWSERS=0.
BROWSER_APPS=("Google Chrome" "Chromium" "Firefox" "Arc" "Brave Browser" "Safari" "Microsoft Edge")
running_browsers=()
for app in "${BROWSER_APPS[@]}"; do
  if osascript -e "tell application \"System Events\" to (name of processes) contains \"$app\"" 2>/dev/null | grep -qi true; then
    running_browsers+=("$app")
  fi
done

if [ "${#running_browsers[@]}" -gt 0 ]; then
  case "${WARDEN_QUIT_BROWSERS:-}" in
    1|y|yes|true)  do_quit=1 ;;
    0|n|no|false)  do_quit=0 ;;
    *)
      if [ -t 0 ]; then
        printf "\n${C1}▶${END} The following browsers are running and need to restart\n"
        printf "  to pick up the new CA trust:\n"
        for app in "${running_browsers[@]}"; do
          printf "    • %s\n" "$app"
        done
        printf "  ${DIM}Each app will prompt about unsaved work, but please save\n"
        printf "  anything important first.${END}\n"
        printf "  Quit them now? [y/N] "
        read -r ans || ans=""
        case "$ans" in y|Y|yes|YES) do_quit=1 ;; *) do_quit=0 ;; esac
      else
        do_quit=0
        note "Non-interactive run — leaving browsers alone. Restart them yourself, or re-run with WARDEN_QUIT_BROWSERS=1."
      fi
      ;;
  esac

  if [ "$do_quit" = "1" ]; then
    for app in "${running_browsers[@]}"; do
      step "Asking $app to quit"
      osascript -e "tell application \"$app\" to quit" >/dev/null 2>&1 || true
    done
    ok "Browsers asked to quit — reopen them to pick up the new trust"
  else
    warn "Skipping browser quit. Restart your browsers manually so they re-read the new CA trust."
  fi
fi

cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  All set. Open Safari/Chrome and visit chatgpt.com (or claude.ai,
  gemini.google.com, perplexity.ai, …) — sensitivity events will appear
  on the dashboard:

      $DASHBOARD_URL

  Open a new terminal so the proxy env vars take effect for CLIs.

  To revert everything (turn proxy off, remove the CA):

      scripts/uninstall-mac.sh
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
