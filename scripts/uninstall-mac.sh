#!/usr/bin/env bash
# Reverts what install-mac.sh did:
#   1. Disables the macOS system HTTP+HTTPS proxy
#   2. Removes the warden / mitmproxy CA from the System keychain
#   3. Optionally deletes the local CA file
#
# Safe to run multiple times. Does not stop the docker stack.

set -euo pipefail

CA_FILE="${CA_FILE:-./mitmproxy-ca.pem}"

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

# ── Detect active service ──────────────────────────────────────────────────
SERVICE=""
while IFS= read -r svc; do
  [ -z "$svc" ] && continue
  if networksetup -getinfo "$svc" 2>/dev/null | grep -qE "^IP address: [0-9]"; then
    SERVICE="$svc"; break
  fi
done < <(networksetup -listallnetworkservices | tail -n +2)

# SAFETY: restore the user's *original* proxy state from the install-time
# snapshot at ~/.config/warden/state.json. Falls back to "all proxies off"
# if no snapshot exists. This protects pre-existing corporate / SOCKS
# proxies from being silently nuked across install→uninstall cycles.
WARDEN_STATE_FILE="$HOME/.config/warden/state.json"
if [ -n "$SERVICE" ]; then
  if [ -f "$WARDEN_STATE_FILE" ] && command -v python3 >/dev/null; then
    step "Restoring pre-warden macOS proxy state from $WARDEN_STATE_FILE"
    eval "$(python3 - "$WARDEN_STATE_FILE" <<'PY'
import json, sys, pathlib, shlex
s = json.loads(pathlib.Path(sys.argv[1]).read_text()).get("mac_networksetup", {})
svc = s.get("service","")
web = s.get("web", {}); sweb = s.get("secure_web", {}); bypass = s.get("bypass", []) or []
def emit(*args): print(" ".join(shlex.quote(a) for a in args))
if svc:
    if web.get("server") and web.get("port"):
        emit("sudo","networksetup","-setwebproxy",svc,web["server"],str(web["port"]))
    emit("sudo","networksetup","-setwebproxystate",svc,"on" if web.get("enabled") else "off")
    if sweb.get("server") and sweb.get("port"):
        emit("sudo","networksetup","-setsecurewebproxy",svc,sweb["server"],str(sweb["port"]))
    emit("sudo","networksetup","-setsecurewebproxystate",svc,"on" if sweb.get("enabled") else "off")
    if bypass:
        emit("sudo","networksetup","-setproxybypassdomains",svc,*bypass)
    else:
        emit("sudo","networksetup","-setproxybypassdomains",svc,"Empty")
PY
)" || warn "Snapshot restore script returned non-zero (proxy may still be off)."
    ok "macOS proxy restored to original state"
  else
    step "No snapshot found — disabling system proxy on '$SERVICE'"
    sudo networksetup -setwebproxystate       "$SERVICE" off || true
    sudo networksetup -setsecurewebproxystate "$SERVICE" off || true
    ok "System proxy off"
  fi
else
  warn "No active network service found — skipping proxy-off step."
fi
# Snapshot is single-use: remove it after restore.
[ -f "$WARDEN_STATE_FILE" ] && rm -f "$WARDEN_STATE_FILE" && ok "Removed proxy-state snapshot"

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

# Symmetric to install: kick trustd so cached "this CA is trusted"
# decisions are dropped immediately. Without this, an already-running
# Chrome/Safari can keep using the in-memory trusted state for an
# already-removed cert, which is confusing both for re-installs (the
# next install starts from a stale baseline) and for sensitive sites
# (a removed-but-still-honored CA is a security smell). Linux has no
# equivalent — this is macOS-only.
if [ "$removed" -gt 0 ]; then
  step "Refreshing macOS trust daemon (so the removal takes effect)"
  sudo killall -HUP trustd 2>/dev/null || true
  ok "Trust daemon refreshed"
fi

# ── Strip the warden proxy block from shell rc files ──────────────────────
# SAFETY: fall back to a sed-based stripper if python3 isn't present
# (some macOS users on a clean install don't have it). Also verify the
# strip actually fired so we don't silently leave a stale block behind.
WARDEN_RC_BEGIN="# >>> warden proxy >>>"
WARDEN_RC_END="# <<< warden proxy <<<"
for rc in "$HOME/.zshrc" "$HOME/.bash_profile" "$HOME/.bashrc"; do
  [ -f "$rc" ] || continue
  if grep -qF "$WARDEN_RC_BEGIN" "$rc" 2>/dev/null; then
    if command -v python3 >/dev/null; then
      python3 - "$rc" "$WARDEN_RC_BEGIN" "$WARDEN_RC_END" <<'PY'
import sys, pathlib, re
rc, begin, end = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(rc)
text = p.read_text()
pattern = re.compile(re.escape(begin) + r"[\s\S]*?" + re.escape(end) + r"\n?", re.MULTILINE)
new = pattern.sub("", text).rstrip() + "\n"
if new != text:
    p.write_text(new)
PY
    else
      sed -i.warden-bak "/^# >>> warden proxy >>>$/,/^# <<< warden proxy <<<$/d" "$rc"
      rm -f "${rc}.warden-bak"
    fi
    if grep -qF "$WARDEN_RC_BEGIN" "$rc" 2>/dev/null; then
      warn "Failed to strip warden block from $rc — please remove the lines between '$WARDEN_RC_BEGIN' and '$WARDEN_RC_END' yourself."
    else
      ok "Stripped warden block from $rc"
    fi
  fi
done

# ── Unwire Claude Code if install-mac.sh wired it up ───────────────────────
CLAUDE_SETTINGS="$HOME/.claude/settings.json"
CA_STABLE="$HOME/.config/warden/mitmproxy-ca.pem"
COMBINED_BUNDLE="$HOME/.config/warden/warden-ca-bundle.pem"
if [ -f "$CLAUDE_SETTINGS" ] && command -v python3 >/dev/null; then
  step "Removing Warden env entries from $CLAUDE_SETTINGS"
  python3 - "$CLAUDE_SETTINGS" <<'PY'
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

# ── Stable CA copy cleanup ────────────────────────────────────────────────
if [ -f "$COMBINED_BUNDLE" ]; then
  rm -f "$COMBINED_BUNDLE"
  ok "Removed combined CA bundle at $COMBINED_BUNDLE"
fi
if [ -f "$CA_STABLE" ]; then
  rm -f "$CA_STABLE"
  ok "Removed stable CA at $CA_STABLE"
fi
# Clean up the warden config dir if empty (state.json already removed).
rmdir "$HOME/.config/warden" 2>/dev/null || true

# ── Optional file cleanup ─────────────────────────────────────────────────
if [ -f "$CA_FILE" ]; then
  step "Deleting $CA_FILE"
  rm -f "$CA_FILE"
  ok "Removed $CA_FILE"
fi

# ── Quit browsers so they re-read trust on next launch ────────────────────
# SAFETY:
#   • Apple Events (osascript) target the real GUI apps only — they can
#     never match a CLI tool that has "chrome" in its argv (unlike pkill -f).
#   • The macOS apps themselves prompt about unsaved tabs/forms, but we
#     ALSO prompt FIRST so the user can save important work before any
#     quit dialog appears.
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
        printf "  to drop the warden CA trust:\n"
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
        warn "Non-interactive run — leaving browsers alone. Restart them yourself, or re-run with WARDEN_QUIT_BROWSERS=1."
      fi
      ;;
  esac

  if [ "$do_quit" = "1" ]; then
    for app in "${running_browsers[@]}"; do
      step "Asking $app to quit"
      osascript -e "tell application \"$app\" to quit" >/dev/null 2>&1 || true
    done
    ok "Browsers closing — reopen them to pick up the trust change"
  else
    warn "Skipping browser quit. Restart your browsers manually so they drop the old CA trust."
  fi
fi

# Stripping the rc block only affects *new* shells. Already-open terminals
# still have HTTP_PROXY / SSL_CERT_FILE etc. exported pointing at files
# we just deleted — that breaks pip and friends until cleared. Print a
# copy-pasteable one-liner.
cat <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  System proxy disabled, CA removed (system + stable copy), terminal
  env vars stripped, Claude Code settings cleaned, browsers closed.
  The Docker stack is still running (run 'docker compose down' to stop).

  ⚠  Already-open terminals still have warden's env vars set. To clean
     the *current* shell (run this in each open terminal, or just open
     a new one):

      unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY \\
            REQUESTS_CA_BUNDLE SSL_CERT_FILE NODE_EXTRA_CA_CERTS \\
            http_proxy https_proxy all_proxy no_proxy

  To start fresh:  bash scripts/install-mac.sh
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
