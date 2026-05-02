#!/usr/bin/env bash
# One-line installer for Linux:
#   1. Waits for warden-proxy + warden-api containers to be healthy
#   2. Pulls the mitmproxy CA out of the container
#   3. Trusts the CA in the system trust store         (1 sudo prompt)
#   4. Trusts the CA in the per-user NSS DB            (Chrome / Chromium / Firefox profile)
#   5. Flips the system-wide HTTP+HTTPS proxy to localhost:8080
#         · GNOME → gsettings org.gnome.system.proxy
#         · Otherwise prints the env-var lines to add to your shell rc
#   6. Adds a localhost bypass so the dashboard itself isn't proxied
#
# After this script finishes, opening chatgpt.com / claude.ai / etc. in a
# GNOME-aware browser routes through Warden automatically. Events appear
# in the dashboard at http://localhost:8090.
#
# To revert everything, run:  scripts/uninstall-linux.sh

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

[ "$(uname -s)" = "Linux" ] || fail "This installer is for Linux. On macOS, run scripts/install-mac.sh."

# Resolve the *invoking* user — when this script runs under sudo we still need
# to apply gsettings to their GNOME session and write the CA into their NSS DB,
# not root's. Without this, the dashboard sits at zero because the user's
# browser never picks up the proxy.
TARGET_USER="${SUDO_USER:-$(id -un)}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
TARGET_UID="$(id -u "$TARGET_USER")"
TARGET_GROUP="$(id -gn "$TARGET_USER" 2>/dev/null || echo "$TARGET_USER")"
[ -n "$TARGET_HOME" ] || fail "Couldn't resolve home directory for user '$TARGET_USER'."

# ── Detect distro family early (used by both the docker installer below and
#       the certutil + system-trust steps further down). ────────────────────
DISTRO_FAMILY="unknown"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${ID_LIKE:-}" in
    *debian*|*ubuntu*) DISTRO_FAMILY="debian" ;;
    *fedora*|*rhel*|*centos*) DISTRO_FAMILY="rhel" ;;
    *arch*|*manjaro*) DISTRO_FAMILY="arch" ;;
    *suse*) DISTRO_FAMILY="suse" ;;
  esac
fi

# ── Docker: auto-install if missing ────────────────────────────────────────
# get.docker.com is the official convenience script — it picks the right
# repo for the detected distro and pulls in the compose plugin too. We
# prefer the distro package manager when we can match it cleanly (avoids
# a curl|sh dance), but fall back to the convenience script otherwise.
install_docker() {
  step "Docker not found on host — installing Docker Engine + compose plugin (sudo required)"
  case "$DISTRO_FAMILY" in
    debian)
      sudo apt-get update -qq
      # Try the distro repo first; fall back to get.docker.com if it doesn't
      # ship docker-compose-plugin (older Debian/Ubuntu).
      if ! sudo apt-get install -y --no-install-recommends docker.io docker-compose-plugin 2>/dev/null; then
        warn "distro repo missing docker-compose-plugin — falling back to get.docker.com"
        curl -fsSL https://get.docker.com -o /tmp/warden-get-docker.sh
        sudo sh /tmp/warden-get-docker.sh
        rm -f /tmp/warden-get-docker.sh
      fi
      ;;
    rhel)
      curl -fsSL https://get.docker.com -o /tmp/warden-get-docker.sh
      sudo sh /tmp/warden-get-docker.sh
      rm -f /tmp/warden-get-docker.sh
      ;;
    arch)
      sudo pacman -S --needed --noconfirm docker docker-compose
      ;;
    suse)
      sudo zypper install -y docker docker-compose
      ;;
    *)
      warn "Unknown distro — using the official get.docker.com convenience script."
      curl -fsSL https://get.docker.com -o /tmp/warden-get-docker.sh
      sudo sh /tmp/warden-get-docker.sh
      rm -f /tmp/warden-get-docker.sh
      ;;
  esac
  # Make the daemon start now AND on reboot; otherwise the wait-loop below
  # hangs waiting for a daemon that systemd won't bring up.
  if command -v systemctl >/dev/null; then
    sudo systemctl enable --now docker >/dev/null 2>&1 || true
  fi
  # Add invoking user to the docker group so subsequent runs don't need sudo.
  # Group membership only takes effect on the next login — warn loudly so the
  # user knows why the *current* run still uses 'sudo docker'.
  if getent group docker >/dev/null && ! id -nG "$TARGET_USER" 2>/dev/null | tr ' ' '\n' | grep -qx docker; then
    sudo usermod -aG docker "$TARGET_USER" || true
    warn "Added $TARGET_USER to the 'docker' group — log out / back in (or run 'newgrp docker') for it to apply."
  fi
  command -v docker >/dev/null || fail "Docker install reported success but 'docker' is still missing — see the package-manager output above."
  ok "Docker installed"
}

if ! command -v docker >/dev/null; then
  install_docker
fi

# Run a command as the invoking user with their session bus + HOME, so that
# gsettings hits their dconf and certutil writes their NSS DB.
run_as_user() {
  if [ "$TARGET_USER" = "$(id -un)" ]; then
    env HOME="$TARGET_HOME" "$@"
  else
    sudo -u "$TARGET_USER" \
      env HOME="$TARGET_HOME" \
          DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${TARGET_UID}/bus" \
          XDG_RUNTIME_DIR="/run/user/${TARGET_UID}" \
          DISPLAY="${DISPLAY:-:0}" \
          "$@"
  fi
}

# certutil (from libnss3-tools / nss-tools) is REQUIRED — Chrome and Firefox
# on Linux read their own per-user NSS DB, not the system trust store. Without
# certutil, the cert never makes it into Chrome and you'll get
# ERR_CERT_AUTHORITY_INVALID. Auto-install where we can.
if ! command -v certutil >/dev/null; then
  step "Installing libnss3-tools / nss-tools (needed to add the CA to Chrome's NSS DB)"
  case "$DISTRO_FAMILY" in
    debian) sudo apt-get update -qq && sudo apt-get install -y --no-install-recommends libnss3-tools ;;
    rhel)   sudo dnf install -y nss-tools 2>/dev/null || sudo yum install -y nss-tools ;;
    arch)   sudo pacman -S --needed --noconfirm nss ;;
    suse)   sudo zypper install -y mozilla-nss-tools ;;
    *)      fail "certutil missing and distro not auto-detected. Install the 'nss-tools' / 'libnss3-tools' package manually, then re-run." ;;
  esac
  command -v certutil >/dev/null || fail "certutil still missing after install attempt — install the NSS tools package for your distro and re-run."
  ok "certutil ready"
fi

# Decide how to call the docker daemon. Some setups run rootful and require
# sudo; others (rootless / user in the 'docker' group) don't. Detect once and
# prefix every daemon command consistently — otherwise 'docker exec' fails
# silently for the regular user and the wait-loop hangs forever.
if docker info >/dev/null 2>&1; then
  DOCKER="docker"
elif sudo docker info >/dev/null 2>&1; then
  DOCKER="sudo docker"
  warn "Docker requires sudo on this host — using 'sudo docker' for daemon commands."
else
  fail "Can't reach the docker daemon as $(id -un) or via sudo. Make sure 'docker compose up' is running."
fi

# Self-heal legacy state from a prior buggy install run, so a non-tech user
# can rely on a single 'install' command (without remembering 'uninstall' first).
# Only touches the *default* CA_FILE path — if the user explicitly set CA_FILE
# to something else via env, we refuse to clobber it.
if [ "$CA_FILE" = "./mitmproxy-ca.pem" ] && [ -e "$CA_FILE" ] && [ ! -w "$CA_FILE" ]; then
  step "Cleaning up stale root-owned $CA_FILE from a prior run"
  sudo rm -f "$CA_FILE"
elif [ -e "$CA_FILE" ] && [ ! -w "$CA_FILE" ]; then
  fail "$CA_FILE exists and isn't writable by $(id -un). It looks like you set CA_FILE to a non-default path; remove it yourself and re-run."
fi
# Older buggy runs may have written gsettings/NSS state under root — clear it
# so the install we're about to do is the only source of truth.
if command -v gsettings >/dev/null; then
  sudo gsettings set org.gnome.system.proxy mode 'none' >/dev/null 2>&1 || true
fi
if sudo test -d /root/.pki/nssdb 2>/dev/null && command -v certutil >/dev/null && \
   sudo certutil -d sql:/root/.pki/nssdb -L 2>/dev/null | grep -q "^${CA_NICKNAME}\b"; then
  sudo certutil -d sql:/root/.pki/nssdb -D -n "$CA_NICKNAME" >/dev/null 2>&1 || true
fi

# ── 1. Wait for warden-proxy + the CA file ─────────────────────────────────
step "Waiting for warden-proxy to be ready (model training can take a few minutes on first boot)"
TRIES=0
until $DOCKER exec warden-proxy test -f /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem 2>/dev/null; do
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

# ── 2. Copy CA out of the container ────────────────────────────────────────
# Tried-and-failed methods on snap-installed Docker:
#   * 'docker cp /tmp/file' → reports success, writes inside snap's confined
#     namespace, host path stays empty.
#   * 'docker exec cat /file > /tmp/file' → exits 0 with no bytes on stdout
#     under snap confinement.
# What works EVERYWHERE: fetch the CA from mitmproxy's own self-served endpoint
# (http://mitm.it/cert/pem) via the proxy. No docker access needed at all, and
# this is the documented retrieval method per the mitmproxy docs.
step "Copying CA → $CA_FILE"
CA_PATH_IN_CTR="/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"
TMP_CA="$(mktemp -t warden-ca.XXXXXXXXXX)"

is_valid_pem() {
  [ -s "$1" ] && grep -q 'BEGIN CERTIFICATE' "$1"
}

copy_method=""

# Method 1 (preferred): fetch via the proxy's mitm.it endpoint.
if [ -z "$copy_method" ]; then
  : > "$TMP_CA"
  if curl -sSf --max-time 10 -x "http://${PROXY_HOST}:${PROXY_PORT}" \
       http://mitm.it/cert/pem -o "$TMP_CA" 2>/dev/null && is_valid_pem "$TMP_CA"; then
    copy_method="mitm.it/cert/pem (via proxy)"
  fi
fi

# Method 2: docker exec ... cat. Works on rootful/rootless engine; usually
# fails on snap-docker but cheap to try.
if [ -z "$copy_method" ]; then
  : > "$TMP_CA"
  if $DOCKER exec warden-proxy cat "$CA_PATH_IN_CTR" > "$TMP_CA" 2>/dev/null && is_valid_pem "$TMP_CA"; then
    copy_method="docker exec cat"
  fi
fi

# Method 3: 'docker cp container:path -' tar-streamed to stdout.
if [ -z "$copy_method" ] && command -v tar >/dev/null; then
  : > "$TMP_CA"
  if $DOCKER cp "warden-proxy:$CA_PATH_IN_CTR" - 2>/dev/null | tar -xO 2>/dev/null > "$TMP_CA" && is_valid_pem "$TMP_CA"; then
    copy_method="docker cp tar-stream"
  fi
fi

# Method 4: read straight from the named volume's mountpoint on the host.
if [ -z "$copy_method" ]; then
  : > "$TMP_CA"
  for vol in al_llm_warden_warden-mitm warden-mitm; do
    mp="$($DOCKER volume inspect "$vol" --format '{{.Mountpoint}}' 2>/dev/null)"
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
  $DOCKER exec warden-proxy ls -la /home/mitmproxy/.mitmproxy/ 2>&1 || true
  echo ""
  fail "All four CA-fetch methods failed. Make sure 'docker compose up' shows warden-proxy as healthy on port 8080."
fi

ok "Fetched via: $copy_method"
sudo chown "$TARGET_USER:$TARGET_GROUP" "$TMP_CA" 2>/dev/null || true
mv -f "$TMP_CA" "$CA_FILE"
if ! is_valid_pem "$CA_FILE"; then
  fail "$CA_FILE is empty or not a PEM after copy. Aborting before we trust garbage."
fi
ok "CA written to $CA_FILE ($(wc -c < "$CA_FILE") bytes)"

# ── 3. Trust the CA in the system store ────────────────────────────────────
step "Trusting the CA in the system trust store (you may be prompted for sudo)"
case "$DISTRO_FAMILY" in
  debian)
    sudo install -m 0644 "$CA_FILE" "/usr/local/share/ca-certificates/${CA_NICKNAME}.crt"
    sudo update-ca-certificates >/dev/null
    ok "CA installed via update-ca-certificates"
    ;;
  rhel)
    sudo install -m 0644 "$CA_FILE" "/etc/pki/ca-trust/source/anchors/${CA_NICKNAME}.crt"
    sudo update-ca-trust extract
    ok "CA installed via update-ca-trust"
    ;;
  arch)
    sudo install -m 0644 "$CA_FILE" "/etc/ca-certificates/trust-source/anchors/${CA_NICKNAME}.crt"
    sudo trust extract-compat
    ok "CA installed via trust extract-compat"
    ;;
  suse)
    sudo install -m 0644 "$CA_FILE" "/etc/pki/trust/anchors/${CA_NICKNAME}.crt"
    sudo update-ca-certificates >/dev/null
    ok "CA installed via update-ca-certificates"
    ;;
  *)
    warn "Unknown distro — couldn't auto-install CA. See README.md for manual steps."
    ;;
esac

# ── 4. Trust the CA in the per-user NSS DB (Chrome / Chromium / Firefox) ───
add_to_nssdb() {
  local db="$1" label="$2" err
  [ -d "$db" ] || run_as_user mkdir -p "$db"
  if [ ! -f "$db/cert9.db" ] && [ ! -f "$db/cert8.db" ]; then
    run_as_user certutil -d "sql:$db" -N --empty-password >/dev/null 2>&1 || true
  fi
  run_as_user certutil -d "sql:$db" -D -n "$CA_NICKNAME" >/dev/null 2>&1 || true
  # First attempt: assume empty password (the common case).
  err="$(run_as_user certutil -d "sql:$db" -A -t "C,," -n "$CA_NICKNAME" -i "$CA_FILE" 2>&1)"
  if [ -z "$err" ]; then
    ok "CA added to $label ($db)"
    return 0
  fi
  # Retry with an empty password file (handles DBs that have a master password
  # set to empty but still demand -f, and gives a clean second try).
  err="$(run_as_user certutil -d "sql:$db" -A -t "C,," -n "$CA_NICKNAME" -i "$CA_FILE" -f /dev/null 2>&1)"
  if [ -z "$err" ]; then
    ok "CA added to $label ($db) [retry with -f /dev/null]"
    return 0
  fi
  warn "Failed to add CA to $label ($db): $err"
  return 1
}

if command -v certutil >/dev/null; then
  step "Trusting the CA in $TARGET_USER's NSS DBs (Chrome / Chromium / Firefox)"
  # Default Chrome / Chromium NSS DB. '|| true' so a single failure here doesn't
  # silently kill the whole installer under set -e — add_to_nssdb already warns
  # with the exact certutil error, and the verify step at the end will fail loud
  # if the cert really didn't land.
  add_to_nssdb "$TARGET_HOME/.pki/nssdb" "Chrome/Chromium" || true
  # Snap-packaged Chrome / Chromium read their own confined NSS DBs.
  for snap_db in "$TARGET_HOME/snap/chromium/current/.pki/nssdb" \
                 "$TARGET_HOME/snap/google-chrome/current/.pki/nssdb"; do
    parent="$(dirname "$snap_db")"
    [ -d "$(dirname "$parent")" ] || continue
    add_to_nssdb "$snap_db" "Snap $(basename "$(dirname "$(dirname "$snap_db")")")" || true
  done
  # Firefox profiles (system + snap).
  for prof in "$TARGET_HOME/.mozilla/firefox"/*.default* \
              "$TARGET_HOME/snap/firefox/common/.mozilla/firefox"/*.default*; do
    [ -d "$prof" ] || continue
    add_to_nssdb "$prof" "Firefox profile $(basename "$prof")" || true
  done
else
  fail "certutil disappeared between install and use — this should not happen."
fi

# ── 5. Flip system proxy ───────────────────────────────────────────────────
# SAFETY: snapshot the user's *current* gsettings proxy state to
# ~/.config/warden/state.json BEFORE we flip anything, so the uninstaller
# can restore an original SOCKS / corporate proxy instead of just turning
# all proxies off. We only write the snapshot if one doesn't already exist
# — this protects against a re-run capturing the warden-flipped state as
# the "original" and cementing it on the next uninstall.
WARDEN_STATE_DIR="$TARGET_HOME/.config/warden"
WARDEN_STATE_FILE="$WARDEN_STATE_DIR/state.json"
run_as_user mkdir -p "$WARDEN_STATE_DIR"

PROXY_SET=0
DESKTOP="${XDG_CURRENT_DESKTOP:-}${DESKTOP_SESSION:+:$DESKTOP_SESSION}"
case "$DESKTOP" in
  *GNOME*|*Unity*|*ubuntu*|*Cinnamon*|*MATE*)
    if command -v gsettings >/dev/null; then
      if ! run_as_user test -f "$WARDEN_STATE_FILE"; then
        step "Snapshotting current GNOME proxy state → $WARDEN_STATE_FILE (so uninstall can restore it)"
        run_as_user python3 - "$WARDEN_STATE_FILE" <<'PY'
import json, subprocess, sys, pathlib
def get(schema, key):
    try:
        return subprocess.check_output(["gsettings","get",schema,key], text=True).strip()
    except Exception:
        return ""
state = {
  "linux_gsettings": {
    "mode":         get("org.gnome.system.proxy",       "mode"),
    "http_host":    get("org.gnome.system.proxy.http",  "host"),
    "http_port":    get("org.gnome.system.proxy.http",  "port"),
    "https_host":   get("org.gnome.system.proxy.https", "host"),
    "https_port":   get("org.gnome.system.proxy.https", "port"),
    "ignore_hosts": get("org.gnome.system.proxy",       "ignore-hosts"),
  }
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(state, indent=2))
PY
        ok "Snapshot written"
      else
        note "Existing $WARDEN_STATE_FILE — keeping the original snapshot intact."
      fi
      step "Enabling GNOME system proxy for $TARGET_USER → ${PROXY_HOST}:${PROXY_PORT}"
      run_as_user gsettings set org.gnome.system.proxy mode 'manual'
      run_as_user gsettings set org.gnome.system.proxy.http  host "$PROXY_HOST"
      run_as_user gsettings set org.gnome.system.proxy.http  port "$PROXY_PORT"
      run_as_user gsettings set org.gnome.system.proxy.https host "$PROXY_HOST"
      run_as_user gsettings set org.gnome.system.proxy.https port "$PROXY_PORT"
      run_as_user gsettings set org.gnome.system.proxy ignore-hosts \
        "['localhost', '127.0.0.0/8', '::1', '169.254.0.0/16']"
      ok "GNOME proxy set"
      PROXY_SET=1
    fi
    ;;
esac

if [ "$PROXY_SET" -eq 0 ]; then
  warn "No supported desktop proxy backend detected ($DESKTOP). Add these lines to your shell rc:"
  cat <<EOF

    export HTTP_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
    export HTTPS_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
    export ALL_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
    export NO_PROXY=localhost,127.0.0.1,::1
EOF
fi

# ─── Terminal-CLI proxy ────────────────────────────────────────────────────
# GNOME's gsettings only routes GNOME-aware GUI apps. Terminal CLIs (curl,
# python, node, claude-code, gh) read HTTP_PROXY/HTTPS_PROXY env vars and
# would otherwise bypass warden entirely. Write the exports to:
#   • ~/.bashrc / ~/.zshrc  (covers new interactive shells)
#   • ~/.config/environment.d/warden-proxy.conf (systemd user manager —
#     covers desktop-launched apps started after next login)
# Idempotent: a marker block is replaced on every run.
step "Wiring terminal CLIs through warden (~/.bashrc, ~/.zshrc, environment.d)"
WARDEN_RC_BEGIN="# >>> warden proxy >>>"
WARDEN_RC_END="# <<< warden proxy <<<"
WARDEN_RC_BLOCK="$WARDEN_RC_BEGIN
export HTTP_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
export HTTPS_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
export ALL_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
export NO_PROXY=localhost,127.0.0.1,::1
export REQUESTS_CA_BUNDLE=$TARGET_HOME/.config/warden/mitmproxy-ca.pem
export SSL_CERT_FILE=$TARGET_HOME/.config/warden/mitmproxy-ca.pem
$WARDEN_RC_END"
# Make sure the stable CA the env block points at exists, even if Claude
# Code wasn't selected — terminal tools need it for TLS verification.
run_as_user mkdir -p "$TARGET_HOME/.config/warden"
run_as_user cp -f "$CA_FILE" "$TARGET_HOME/.config/warden/mitmproxy-ca.pem"

for rc in "$TARGET_HOME/.bashrc" "$TARGET_HOME/.zshrc"; do
  [ -f "$rc" ] || continue
  # Strip any prior warden block, then append the fresh one.
  run_as_user python3 - "$rc" "$WARDEN_RC_BEGIN" "$WARDEN_RC_END" "$WARDEN_RC_BLOCK" <<'PY'
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

# systemd user environment.d — picked up on next login by user services /
# desktop-launched apps. Per-user, no sudo needed for the file itself.
ENVD="$TARGET_HOME/.config/environment.d/warden-proxy.conf"
run_as_user mkdir -p "$(dirname "$ENVD")"
run_as_user tee "$ENVD" >/dev/null <<EOF
HTTP_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
HTTPS_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
ALL_PROXY=http://${PROXY_HOST}:${PROXY_PORT}
NO_PROXY=localhost,127.0.0.1,::1
REQUESTS_CA_BUNDLE=$TARGET_HOME/.config/warden/mitmproxy-ca.pem
SSL_CERT_FILE=$TARGET_HOME/.config/warden/mitmproxy-ca.pem
EOF
ok "Wrote $ENVD"
note "Open a new terminal (or run 'source ~/.bashrc') for env vars to take effect."

# ── 6. Verify ──────────────────────────────────────────────────────────────
step "Verifying the proxy is in the path"
if curl -sS --max-time 8 --cacert "$CA_FILE" \
     --proxy "http://${PROXY_HOST}:${PROXY_PORT}" \
     -o /dev/null -w "%{http_code}\n" \
     -H "Authorization: Bearer sk-fake-validator-token-123456789" \
     https://api.openai.com/v1/models 2>/dev/null | grep -qE "^[1-5][0-9][0-9]$"; then
  ok "Reached api.openai.com via the proxy"
else
  warn "Couldn't reach api.openai.com (offline?) — that's fine; the proxy is still active."
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
  # Copy the CA to a stable absolute path so settings.json doesn't break if the
  # user moves the repo. ~/.config/warden/mitmproxy-ca.pem is the canonical home.
  CA_STABLE_DIR="$TARGET_HOME/.config/warden"
  CA_STABLE="$CA_STABLE_DIR/mitmproxy-ca.pem"
  run_as_user mkdir -p "$CA_STABLE_DIR"
  run_as_user cp -f "$CA_FILE" "$CA_STABLE"
  ok "CA copied to $CA_STABLE (stable path for Claude Code)"

  CLAUDE_DIR="$TARGET_HOME/.claude"
  CLAUDE_SETTINGS="$CLAUDE_DIR/settings.json"
  run_as_user mkdir -p "$CLAUDE_DIR"

  # SAFETY: keep a one-time pristine backup of the user's pre-warden
  # settings. We never overwrite it on subsequent runs, so even if a
  # user inspects/diffs later they can see exactly what we changed.
  if [ -f "$CLAUDE_SETTINGS" ] && [ ! -f "$CLAUDE_SETTINGS.warden-pre-patch.bak" ]; then
    run_as_user cp -f "$CLAUDE_SETTINGS" "$CLAUDE_SETTINGS.warden-pre-patch.bak"
    ok "Backed up original settings to $CLAUDE_SETTINGS.warden-pre-patch.bak"
  fi

  run_as_user python3 - "$CLAUDE_SETTINGS" "$CA_STABLE" "http://${PROXY_HOST}:${PROXY_PORT}" <<'PY'
import json, os, sys, pathlib
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

# Decide whether to run the Claude Code step:
#   WARDEN_CLAUDE_CODE=1  → auto-yes (CI / scripted)
#   WARDEN_CLAUDE_CODE=0  → auto-no
#   unset + interactive   → ask the user
#   unset + non-interactive → skip with a hint
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

# ── 8. Verify the cert in the NSS DB matches what mitmproxy is actually
#       serving. If they disagree, the install "succeeded" but Chrome will
#       still throw ERR_CERT_AUTHORITY_INVALID — fail loudly here instead.
step "Verifying NSS-DB trust matches the live proxy CA"
DISK_FP="$(openssl x509 -in "$CA_FILE" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
NSS_FP="$(run_as_user certutil -d "sql:$TARGET_HOME/.pki/nssdb" -L -n "$CA_NICKNAME" 2>/dev/null \
          | awk -F': ' '/Fingerprint \(SHA-256\)/{getline; gsub(/^[ \t]+/,"",$0); print toupper($0); exit}')"
if [ -n "$DISK_FP" ] && [ -n "$NSS_FP" ] && [ "${DISK_FP// /}" = "${NSS_FP// /}" ]; then
  ok "Fingerprints match (${DISK_FP:0:23}…)"
elif [ -z "$NSS_FP" ]; then
  fail "warden-mitmproxy not found in $TARGET_HOME/.pki/nssdb after install. Chrome will reject the cert. Check that 'libnss3-tools' installed cleanly and re-run."
else
  warn "NSS-DB fingerprint differs from disk CA — Chrome will still reject. Forcing a re-add."
  run_as_user certutil -d "sql:$TARGET_HOME/.pki/nssdb" -D -n "$CA_NICKNAME" >/dev/null 2>&1 || true
  run_as_user certutil -d "sql:$TARGET_HOME/.pki/nssdb" -A -t "C,," -n "$CA_NICKNAME" -i "$CA_FILE"
  ok "Re-added; re-verify with 'certutil -d sql:\$HOME/.pki/nssdb -L -n $CA_NICKNAME'"
fi

# ── 9. Force-quit browsers so they re-read NSS trust on next launch ────────
# SAFETY: match by *exact* binary name with `pgrep -x`, not `-f` against the
# full cmdline. The old `-f 'chrome'` regex would also kill chromedriver,
# chrome-pdf-helper, mychrome-tool, anything with "chrome" in its argv.
BROWSER_BINS="chrome chromium chromium-browser google-chrome google-chrome-stable firefox firefox-bin firefox-esr"
browsers_alive() {
  for proc in $BROWSER_BINS; do
    pgrep -u "$TARGET_USER" -x "$proc" >/dev/null 2>&1 && return 0
  done
  return 1
}
if browsers_alive; then
  step "Closing Chrome / Chromium / Firefox so they re-read NSS trust on next launch"
  for proc in $BROWSER_BINS; do
    run_as_user pkill -x "$proc" >/dev/null 2>&1 || true
  done
  sleep 1
  for proc in $BROWSER_BINS; do
    run_as_user pkill -9 -x "$proc" >/dev/null 2>&1 || true
  done
  for _ in 1 2 3 4 5; do
    browsers_alive || break
    sleep 1
  done
  if browsers_alive; then
    warn "Some browser processes are still alive after SIGKILL — close any remaining windows manually before reopening."
  else
    ok "Browsers closed — reopen them to pick up the new trust"
  fi
fi

cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  All set. Sensitivity events will appear on the dashboard:

      $DASHBOARD_URL

  Open chatgpt.com / claude.ai / gemini.google.com / etc. in a
  fresh Chrome window. The cert warning should be gone — we already
  closed Chrome for you so the new trust is picked up on next launch.

  If you still get ERR_CERT_AUTHORITY_INVALID, check what NSS DBs your
  browser actually reads:

      certutil -d sql:\$HOME/.pki/nssdb -L | grep $CA_NICKNAME
      ls -la \$HOME/snap/*/current/.pki/nssdb 2>/dev/null

  To revert everything (turn proxy off, remove the CA):

      scripts/uninstall-linux.sh
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
