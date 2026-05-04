#!/usr/bin/env bash
# Reverts what install-linux.sh did:
#   1. Disables the GNOME system HTTP+HTTPS proxy (if applicable)
#   2. Removes the warden / mitmproxy CA from the system trust store
#   3. Removes the CA from the per-user NSS DB and Firefox profiles
#   4. Optionally deletes the local CA file
#
# Safe to run multiple times. Does not stop the docker stack.

set -euo pipefail

CA_FILE="${CA_FILE:-./mitmproxy-ca.pem}"
CA_NICKNAME="warden-mitmproxy"

# ── Brand logo (printed before any other output for instant recall) ────────
print_logo() {
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
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

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C1='\033[1;35m'; OK='\033[32m✔\033[0m'; WARN='\033[33m!\033[0m'; DIM='\033[2m'; END='\033[0m'
else
  C1=''; OK='[ok]'; WARN='[warn]'; DIM=''; END=''
fi
step() { printf "${C1}▶${END} %s\n" "$*"; }
ok()   { printf "  %b %s\n" "$OK"   "$*"; }
warn() { printf "  %b %s\n" "$WARN" "$*"; }

[ "$(uname -s)" = "Linux" ] || { warn "This uninstaller is for Linux. On macOS, run scripts/uninstall-mac.sh."; exit 0; }

# Resolve the invoking user so gsettings/certutil hit *their* session/NSS DB
# even when this script is run via sudo.
TARGET_USER="${SUDO_USER:-$(id -un)}"
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
TARGET_UID="$(id -u "$TARGET_USER")"

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

# ── Detect distro family ────────────────────────────────────────────────────
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

# ── 1. Restore pre-warden GNOME proxy state from snapshot, or disable ─────
# SAFETY: the installer wrote ~/.config/warden/state.json with the *original*
# gsettings values before flipping anything. Restore those; only fall back
# to mode=none if no snapshot exists. This keeps a user's pre-existing
# corporate / SOCKS proxy intact across install→uninstall cycles.
WARDEN_STATE_FILE="$TARGET_HOME/.config/warden/state.json"
DESKTOP="${XDG_CURRENT_DESKTOP:-}${DESKTOP_SESSION:+:$DESKTOP_SESSION}"
case "$DESKTOP" in
  *GNOME*|*Unity*|*ubuntu*|*Cinnamon*|*MATE*)
    if command -v gsettings >/dev/null; then
      if run_as_user test -f "$WARDEN_STATE_FILE"; then
        step "Restoring pre-warden GNOME proxy state from $WARDEN_STATE_FILE"
        run_as_user python3 - "$WARDEN_STATE_FILE" <<'PY'
import json, subprocess, sys, pathlib
state = json.loads(pathlib.Path(sys.argv[1]).read_text()).get("linux_gsettings", {})
def setv(schema, key, val):
    if val == "" or val is None: return
    subprocess.call(["gsettings","set",schema,key,val])
mode = state.get("mode") or "'none'"
setv("org.gnome.system.proxy.http",  "host",  state.get("http_host"))
setv("org.gnome.system.proxy.http",  "port",  state.get("http_port"))
setv("org.gnome.system.proxy.https", "host",  state.get("https_host"))
setv("org.gnome.system.proxy.https", "port",  state.get("https_port"))
setv("org.gnome.system.proxy",       "ignore-hosts", state.get("ignore_hosts"))
setv("org.gnome.system.proxy",       "mode", mode)
PY
        ok "GNOME proxy restored to original state"
      else
        step "No snapshot found — disabling GNOME system proxy for $TARGET_USER"
        run_as_user gsettings set org.gnome.system.proxy mode 'none' || true
        ok "GNOME proxy off (user session)"
      fi
    fi
    ;;
  *)
    warn "Non-GNOME desktop ($DESKTOP) — if you set HTTP_PROXY/HTTPS_PROXY env vars by hand, unset them yourself."
    ;;
esac
# Legacy cleanup: a previous buggy install run may have written the proxy to
# root's dconf instead of the user's. Clear it silently.
if command -v gsettings >/dev/null; then
  sudo gsettings set org.gnome.system.proxy mode 'none' >/dev/null 2>&1 || true
fi
# Snapshot is single-use: remove it after restore so the next install
# captures a fresh baseline.
[ -f "$WARDEN_STATE_FILE" ] && rm -f "$WARDEN_STATE_FILE" && ok "Removed proxy-state snapshot"

# ── 2. Remove CA from the system trust store ───────────────────────────────
step "Removing mitmproxy CA from system trust store"
removed_system=0
case "$DISTRO_FAMILY" in
  debian|suse)
    for f in "/usr/local/share/ca-certificates/${CA_NICKNAME}.crt" \
             "/etc/pki/trust/anchors/${CA_NICKNAME}.crt"; do
      if [ -f "$f" ]; then
        sudo rm -f "$f"
        removed_system=$((removed_system + 1))
      fi
    done
    [ "$removed_system" -gt 0 ] && sudo update-ca-certificates --fresh >/dev/null 2>&1 || \
      sudo update-ca-certificates >/dev/null 2>&1 || true
    ;;
  rhel)
    f="/etc/pki/ca-trust/source/anchors/${CA_NICKNAME}.crt"
    if [ -f "$f" ]; then
      sudo rm -f "$f"; removed_system=1
      sudo update-ca-trust extract || true
    fi
    ;;
  arch)
    f="/etc/ca-certificates/trust-source/anchors/${CA_NICKNAME}.crt"
    if [ -f "$f" ]; then
      sudo rm -f "$f"; removed_system=1
      sudo trust extract-compat || true
    fi
    ;;
esac
if [ "$removed_system" -gt 0 ]; then
  ok "Removed CA from system trust store"
else
  warn "No warden CA found in system trust store (already clean)."
fi

# ── 3. Remove CA from per-user NSS DBs ─────────────────────────────────────
if command -v certutil >/dev/null; then
  step "Removing CA from $TARGET_USER's NSS DB(s)"
  removed_nss=0
  for db in "$TARGET_HOME/.pki/nssdb" \
            "$TARGET_HOME/snap/chromium/current/.pki/nssdb" \
            "$TARGET_HOME/snap/google-chrome/current/.pki/nssdb" \
            "$TARGET_HOME/.mozilla/firefox"/*.default* \
            "$TARGET_HOME/snap/firefox/common/.mozilla/firefox"/*.default*; do
    [ -d "$db" ] || continue
    if run_as_user certutil -d "sql:$db" -L 2>/dev/null | grep -q "^${CA_NICKNAME}\b"; then
      run_as_user certutil -d "sql:$db" -D -n "$CA_NICKNAME" >/dev/null 2>&1 || true
      removed_nss=$((removed_nss + 1))
    fi
  done
  if [ "$removed_nss" -gt 0 ]; then
    ok "Removed CA from $removed_nss NSS DB(s)"
  else
    warn "No warden CA found in NSS DBs (already clean)."
  fi
  # Legacy cleanup: prior buggy install runs landed the cert in /root/.pki/nssdb.
  if sudo test -d /root/.pki/nssdb 2>/dev/null && \
     sudo certutil -d sql:/root/.pki/nssdb -L 2>/dev/null | grep -q "^${CA_NICKNAME}\b"; then
    sudo certutil -d sql:/root/.pki/nssdb -D -n "$CA_NICKNAME" >/dev/null 2>&1 || true
    ok "Removed legacy CA from /root/.pki/nssdb"
  fi
fi

# ── X. Strip the warden proxy block from shell rc files + environment.d ───
WARDEN_RC_BEGIN="# >>> warden proxy >>>"
WARDEN_RC_END="# <<< warden proxy <<<"
for rc in "$TARGET_HOME/.bashrc" "$TARGET_HOME/.zshrc"; do
  [ -f "$rc" ] || continue
  if grep -qF "$WARDEN_RC_BEGIN" "$rc" 2>/dev/null; then
    run_as_user python3 - "$rc" "$WARDEN_RC_BEGIN" "$WARDEN_RC_END" <<'PY'
import sys, pathlib, re
rc, begin, end = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(rc)
text = p.read_text()
pattern = re.compile(re.escape(begin) + r"[\s\S]*?" + re.escape(end) + r"\n?", re.MULTILINE)
new = pattern.sub("", text).rstrip() + "\n"
if new != text:
    p.write_text(new)
PY
    ok "Stripped warden block from $rc"
  fi
done
ENVD="$TARGET_HOME/.config/environment.d/warden-proxy.conf"
[ -f "$ENVD" ] && rm -f "$ENVD" && ok "Removed $ENVD"

# ── 4. Unwire Claude Code if install-linux.sh wired it up ──────────────────
CLAUDE_SETTINGS="$TARGET_HOME/.claude/settings.json"
CA_STABLE="$TARGET_HOME/.config/warden/mitmproxy-ca.pem"
if [ -f "$CLAUDE_SETTINGS" ] && command -v python3 >/dev/null; then
  step "Removing Warden env entries from $CLAUDE_SETTINGS"
  run_as_user python3 - "$CLAUDE_SETTINGS" <<'PY'
import json, sys, pathlib
p = pathlib.Path(sys.argv[1])
try:
    data = json.loads(p.read_text())
except (json.JSONDecodeError, FileNotFoundError):
    sys.exit(0)
if not isinstance(data, dict): sys.exit(0)
env = data.get("env")
if not isinstance(env, dict): sys.exit(0)
removed = False
for k in ("HTTPS_PROXY", "HTTP_PROXY", "NODE_EXTRA_CA_CERTS"):
    if k in env:
        del env[k]; removed = True
if not env:
    data.pop("env", None)
else:
    data["env"] = env
if removed:
    p.write_text(json.dumps(data, indent=2) + "\n")
PY
  ok "Cleaned Claude Code settings"
fi
if [ -f "$CA_STABLE" ]; then
  rm -f "$CA_STABLE" 2>/dev/null || sudo rm -f "$CA_STABLE"
  rmdir "$(dirname "$CA_STABLE")" 2>/dev/null || true
  ok "Removed stable CA at $CA_STABLE"
fi

# ── 5. Local CA file cleanup (force, since prior runs may have made it root-owned) ─
if [ -e "$CA_FILE" ]; then
  step "Deleting $CA_FILE"
  rm -f "$CA_FILE" 2>/dev/null || sudo rm -f "$CA_FILE"
  ok "Removed $CA_FILE"
fi

# ── 6. Quit browsers so they re-read trust on next launch ─────────────────
# SAFETY:
#   • Match by exact binary name (not -f against full cmdline) so we can't
#     accidentally kill `chromedriver`, `chrome-pdf-helper`, etc.
#   • Linux browsers DON'T prompt before SIGTERM. Always ask the user
#     first, listing exactly which processes will die, so they can save
#     unsaved work.
#   • Skippable in non-interactive runs via WARDEN_QUIT_BROWSERS=0.
BROWSER_BINS="chrome chromium chromium-browser google-chrome google-chrome-stable firefox firefox-bin firefox-esr"
running_browser_bins=""
for proc in $BROWSER_BINS; do
  if pgrep -u "$TARGET_USER" -x "$proc" >/dev/null 2>&1; then
    running_browser_bins="$running_browser_bins $proc"
  fi
done

if [ -n "$running_browser_bins" ]; then
  case "${WARDEN_QUIT_BROWSERS:-}" in
    1|y|yes|true)  do_quit=1 ;;
    0|n|no|false)  do_quit=0 ;;
    *)
      if [ -t 0 ]; then
        printf "\n${C1}▶${END} The following browser processes are running and need to\n"
        printf "  restart to drop the warden CA trust:\n"
        for proc in $running_browser_bins; do
          printf "    • %s\n" "$proc"
        done
        printf "  ${DIM}This sends SIGTERM. Session restore recovers tabs, but\n"
        printf "  unsubmitted forms / unsaved drafts will be lost — please save\n"
        printf "  anything important first.${END}\n"
        printf "  Quit them now? [y/N] "
        read -r ans </dev/tty || ans=""
        case "$ans" in y|Y|yes|YES) do_quit=1 ;; *) do_quit=0 ;; esac
      else
        do_quit=0
        warn "Non-interactive run — leaving browsers alone. Restart them yourself, or re-run with WARDEN_QUIT_BROWSERS=1."
      fi
      ;;
  esac

  if [ "$do_quit" = "1" ]; then
    step "Closing Chrome / Chromium / Firefox so they drop the old CA trust"
    for proc in $running_browser_bins; do
      run_as_user pkill -x "$proc" >/dev/null 2>&1 || true
    done
    sleep 1
    ok "Browsers closed"
  else
    warn "Skipping browser quit. Restart your browsers manually so they drop the old CA trust."
  fi
fi

cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  System proxy disabled, CA removed (user + legacy root state),
  browsers closed. The Docker stack is still running — run
  'docker compose down' to stop it.

  To start fresh:  bash scripts/install-linux.sh
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
