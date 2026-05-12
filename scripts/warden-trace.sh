#!/usr/bin/env bash
# warden-trace.sh — surgical layer-by-layer trace for the
# "internet stops working after install-mac.sh" failure mode.
#
# Run AFTER `bash scripts/install-mac.sh` (i.e. with warden proxy ON,
# system proxy enabled, env vars exported in current shell).
#
# Output:
#   warden-trace-<timestamp>/SUMMARY.txt      — pass/fail per layer + verdict
#   warden-trace-<timestamp>/<layer>.log      — raw command output per layer
#   warden-trace-<timestamp>/mitm.live.log    — mitmdump container log captured
#                                                during the host probes
#
# What this answers, in order:
#   L0  Containers up?                     (proxy/api healthy, MTU 1380 in net)
#   L1  System proxy actually pointed at warden? (networksetup + scutil + env)
#   L2  Is 127.0.0.1:8080 reachable raw?   (TCP connect + bind mode)
#   L3  Cert chain trust — disk vs running container vs System keychain
#         (3-way fingerprint match — any drift = browsers/CLIs reject)
#   L4  Host → proxy → MITM host TLS (api.anthropic.com)
#         (a) without --cacert (relies on System keychain + NODE/SSL env vars)
#         (b) with explicit --cacert (proves chain works if (a) fails)
#   L5  Host → proxy → passthrough host TLS (mail.google.com, www.google.com)
#         (must show real Google issuer, NOT mitmproxy)
#   L6  Container → upstream raw (proves egress + MTU still healthy)
#   L7  Direct (env-stripped) probe to passthrough host
#         (sanity — if this fails too, host network itself is broken)
#   L8  mitmdump live log during all probes — addon errors, handshake fails
#
# Pass/fail is decided by exit code AND HTTP code AND issuer match.
# Anything that times out is marked TIMEOUT (never silent).

set +e
shopt -s nullglob 2>/dev/null

TS=$(date +%Y%m%d-%H%M%S)
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/warden-trace-$TS"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/SUMMARY.txt"
MITM_LOG="$OUT_DIR/mitm.live.log"

# ── ANSI colours (TTY only) ───────────────────────────────────────────────
if [ -t 1 ]; then
  C_OK='\033[32m'; C_FAIL='\033[31m'; C_WARN='\033[33m'
  C_INFO='\033[36m'; C_DIM='\033[2m'; C_BOLD='\033[1m'; C_END='\033[0m'
else
  C_OK=''; C_FAIL=''; C_WARN=''; C_INFO=''; C_DIM=''; C_BOLD=''; C_END=''
fi

# ── Internal helpers ──────────────────────────────────────────────────────
declare -a RESULTS  # entries like "L1|PASS|short note" appended in order

record() {
  # record <layer> <PASS|FAIL|WARN|SKIP> <one-line note>
  RESULTS+=("$1|$2|$3")
  case "$2" in
    PASS) printf "  ${C_OK}✔${C_END} %s — %s\n" "$1" "$3" ;;
    FAIL) printf "  ${C_FAIL}✘${C_END} %s — %s\n" "$1" "$3" ;;
    WARN) printf "  ${C_WARN}!${C_END} %s — %s\n" "$1" "$3" ;;
    SKIP) printf "  ${C_DIM}–${C_END} %s — %s\n" "$1" "$3" ;;
  esac
}

section() {
  printf "\n${C_BOLD}${C_INFO}── %s ──${C_END}\n" "$*"
}

# Run a command with hard timeout, full output to per-layer log file.
# Usage: run_to <seconds> <log-basename> <cmd...>
run_to() {
  local t="$1" base="$2"; shift 2
  local logf="$OUT_DIR/$base.log"
  printf '$ %s\n\n' "$*" > "$logf"
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout --preserve-status "$t" "$@" >>"$logf" 2>&1
    local rc=$?
  else
    ( "$@" ) >>"$logf" 2>&1 &
    local pid=$!
    ( sleep "$t" && kill -KILL "$pid" 2>/dev/null ) &
    local watcher=$!
    wait "$pid" 2>/dev/null
    local rc=$?
    kill -KILL "$watcher" 2>/dev/null
  fi
  printf '\n[exit=%s]\n' "$rc" >> "$logf"
  return "$rc"
}

# ── Header ────────────────────────────────────────────────────────────────
{
  echo "warden-trace @ $(date)"
  echo "host:  $(uname -a)"
  echo "out:   $OUT_DIR"
} > "$SUMMARY"

printf "${C_BOLD}warden-trace${C_END}  ${C_DIM}→ %s${C_END}\n" "$OUT_DIR"

# ── L0: Container health + compose MTU ────────────────────────────────────
section "L0  containers + compose"
run_to 5 L0_docker_ps docker ps --format '{{.Names}}\t{{.Status}}\t{{.Ports}}'
PROXY_LINE=$(grep -E '^warden-proxy\b' "$OUT_DIR/L0_docker_ps.log" 2>/dev/null)
API_LINE=$(grep -E '^warden-api\b'   "$OUT_DIR/L0_docker_ps.log" 2>/dev/null)

if echo "$PROXY_LINE" | grep -q 'Up '; then
  if echo "$PROXY_LINE" | grep -q '127\.0\.0\.1:8080->8080'; then
    record L0a PASS "warden-proxy up, bound to 127.0.0.1:8080"
  else
    record L0a FAIL "warden-proxy up but not bound to 127.0.0.1:8080 — see L0_docker_ps.log"
  fi
else
  record L0a FAIL "warden-proxy not running — start with 'docker compose up -d'"
fi

if echo "$API_LINE" | grep -q 'Up '; then
  record L0b PASS "warden-api up"
else
  record L0b WARN "warden-api not up — dashboard won't work but proxy can still pass traffic"
fi

run_to 5 L0_compose_mtu grep -A5 'warden-net:' "$ROOT/docker-compose.yml"
if grep -q 'mtu: 1380' "$OUT_DIR/L0_compose_mtu.log"; then
  record L0c PASS "compose still has MTU 1380 fix"
else
  record L0c FAIL "MTU 1380 missing from docker-compose.yml — TLS will hang inside container"
fi

# Confirm container actually inherited that MTU.
run_to 5 L0_container_mtu docker exec warden-proxy sh -c 'ip link show eth0 2>/dev/null || ifconfig eth0 2>/dev/null'
if grep -qE 'mtu 1380|MTU:1380' "$OUT_DIR/L0_container_mtu.log"; then
  record L0d PASS "container eth0 mtu=1380 confirmed"
elif grep -qE 'mtu [0-9]+' "$OUT_DIR/L0_container_mtu.log"; then
  ACTUAL_MTU=$(grep -oE 'mtu [0-9]+' "$OUT_DIR/L0_container_mtu.log" | head -1 | awk '{print $2}')
  record L0d FAIL "container eth0 mtu=$ACTUAL_MTU (expected 1380) — recreate network: docker compose down && docker compose up -d"
else
  record L0d WARN "couldn't read container MTU — see L0_container_mtu.log"
fi

# ── L1: System proxy state vs env ─────────────────────────────────────────
section "L1  system proxy + shell env"

ACTIVE_SVC=""
while IFS= read -r svc; do
  [ -z "$svc" ] && continue
  case "$svc" in "An asterisk"*|"") continue ;; esac
  if networksetup -getinfo "$svc" 2>/dev/null | grep -qE '^IP address: [0-9]'; then
    ACTIVE_SVC="$svc"; break
  fi
done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)

{
  echo "active service: $ACTIVE_SVC"
  echo
  echo "-- networksetup -getwebproxy --"
  networksetup -getwebproxy "$ACTIVE_SVC" 2>&1
  echo "-- networksetup -getsecurewebproxy --"
  networksetup -getsecurewebproxy "$ACTIVE_SVC" 2>&1
  echo "-- networksetup -getproxybypassdomains --"
  networksetup -getproxybypassdomains "$ACTIVE_SVC" 2>&1
  echo "-- scutil --proxy --"
  scutil --proxy 2>&1
  echo "-- env --"
  echo "HTTP_PROXY=$HTTP_PROXY"
  echo "HTTPS_PROXY=$HTTPS_PROXY"
  echo "ALL_PROXY=$ALL_PROXY"
  echo "NO_PROXY=$NO_PROXY"
  echo "REQUESTS_CA_BUNDLE=$REQUESTS_CA_BUNDLE"
  echo "SSL_CERT_FILE=$SSL_CERT_FILE"
  echo "NODE_EXTRA_CA_CERTS=$NODE_EXTRA_CA_CERTS"
} > "$OUT_DIR/L1_proxy_state.log"

WEB_ON=$(networksetup -getwebproxy "$ACTIVE_SVC" 2>&1 | awk -F': ' '/Enabled/{print $2}')
WEB_SRV=$(networksetup -getwebproxy "$ACTIVE_SVC" 2>&1 | awk -F': ' '/Server/{print $2}')
WEB_PORT=$(networksetup -getwebproxy "$ACTIVE_SVC" 2>&1 | awk -F': ' '/Port/{print $2}')
SEC_ON=$(networksetup -getsecurewebproxy "$ACTIVE_SVC" 2>&1 | awk -F': ' '/Enabled/{print $2}')

if [ "$WEB_ON" = "Yes" ] && [ "$SEC_ON" = "Yes" ] && [ "$WEB_SRV" = "127.0.0.1" ] && [ "$WEB_PORT" = "8080" ]; then
  record L1a PASS "system proxy = 127.0.0.1:8080 on '$ACTIVE_SVC'"
else
  record L1a FAIL "system proxy mis-set: web=$WEB_ON@$WEB_SRV:$WEB_PORT secure=$SEC_ON — re-run install-mac.sh"
fi

if [ "$HTTPS_PROXY" = "http://127.0.0.1:8080" ] || [ "$HTTPS_PROXY" = "http://127.0.0.1:8080/" ]; then
  record L1b PASS "shell HTTPS_PROXY exported"
else
  record L1b WARN "HTTPS_PROXY='$HTTPS_PROXY' (expected http://127.0.0.1:8080) — open new shell or 'source ~/.zshrc'"
fi

if [ -f "$NODE_EXTRA_CA_CERTS" ] 2>/dev/null; then
  record L1c PASS "NODE_EXTRA_CA_CERTS file present"
else
  record L1c WARN "NODE_EXTRA_CA_CERTS='$NODE_EXTRA_CA_CERTS' — Claude Code etc. will reject MITM cert"
fi

# ── L2: 127.0.0.1:8080 raw reachability ───────────────────────────────────
section "L2  raw TCP to 127.0.0.1:8080"
run_to 5 L2_lsof lsof -nP -iTCP:8080 -sTCP:LISTEN
LISTEN_LINE=$(grep -E ':8080 \(LISTEN\)' "$OUT_DIR/L2_lsof.log" 2>/dev/null | head -1)
if echo "$LISTEN_LINE" | grep -q '127\.0\.0\.1:8080'; then
  record L2a PASS "127.0.0.1:8080 listener bound (loopback only — good)"
elif echo "$LISTEN_LINE" | grep -qE '\*:8080|0\.0\.0\.0:8080'; then
  record L2a WARN "8080 bound to 0.0.0.0 — open relay risk; expected 127.0.0.1"
elif [ -z "$LISTEN_LINE" ]; then
  record L2a FAIL "nothing listening on :8080 — proxy isn't reachable"
fi

run_to 3 L2_tcp /usr/bin/nc -zv 127.0.0.1 8080
if grep -qiE 'succeeded|open' "$OUT_DIR/L2_tcp.log"; then
  record L2b PASS "TCP connect to 127.0.0.1:8080 succeeded"
else
  record L2b FAIL "TCP connect to 127.0.0.1:8080 failed — see L2_tcp.log"
fi

# Plain HTTP through the proxy — proves request forwarding works without TLS.
run_to 12 L2_http_plain /usr/bin/curl -sS --max-time 10 -x http://127.0.0.1:8080 \
  -o /dev/null -w "%{http_code} %{time_total}s\n" \
  http://example.com/
if [ "$(tail -1 "$OUT_DIR/L2_http_plain.log" | awk '{print $1}')" = "200" ]; then
  record L2c PASS "plain HTTP through proxy: 200 OK"
else
  CODE=$(tail -1 "$OUT_DIR/L2_http_plain.log" 2>/dev/null)
  record L2c FAIL "plain HTTP through proxy failed: $CODE — proxy can't reach upstream OR forwarding broken"
fi

# ── L3: Cert chain — three-way fingerprint match + stale CA scan ────────
section "L3  cert chain — fingerprint check + stale CA scan"

CA_DISK="$HOME/.config/warden/mitmproxy-ca.pem"
CA_BUNDLE="$HOME/.config/warden/warden-ca-bundle.pem"

DISK_FP=""
KC_FP=""
CTR_FP=""

# L3-pre: scan ALL keychains for mitmproxy CAs. >1 anywhere = stale cache,
# which is the classic "Google fails but other sites work" cause: HSTS-pinned
# Google domains lock onto whichever CA Chrome saw first; if both old + new
# CAs are trusted, Apple Secure Transport may pick the old one for verifier
# decisions made before reinstall. Telegram/LinkedIn aren't HSTS-pinned in
# Chrome's static list to the same depth so they survive.
CA_TMPDIR="$OUT_DIR/_ca_tmp"
mkdir -p "$CA_TMPDIR"
{
  echo "-- mitmproxy CA inventory across keychains --"
  for kc in \
    /Library/Keychains/System.keychain \
    "$HOME/Library/Keychains/login.keychain-db" \
    /System/Library/Keychains/SystemRootCertificates.keychain
  do
    echo ""
    echo "[$kc]"
    n=$(security find-certificate -a -c mitmproxy "$kc" 2>/dev/null | grep -c 'keychain:')
    echo "count: $n"
    if [ "$n" -gt 0 ]; then
      kcb="$(basename "$kc")"
      pemf="$CA_TMPDIR/$kcb.pem"
      security find-certificate -a -c mitmproxy -p "$kc" 2>/dev/null > "$pemf"
      # Split a multi-PEM file into per-cert PEMs, then fingerprint each.
      awk -v base="$CA_TMPDIR/$kcb" '
        /-----BEGIN CERTIFICATE-----/ { i++; out=base"."i".pem" }
        out { print > out }
      ' "$pemf"
      i=1
      while [ -f "$CA_TMPDIR/$kcb.$i.pem" ]; do
        echo "  cert $i:"
        openssl x509 -in "$CA_TMPDIR/$kcb.$i.pem" -noout -fingerprint -sha256 -subject -dates 2>&1 \
          | sed 's/^/    /'
        i=$((i+1))
      done
    fi
  done
} > "$OUT_DIR/L3_ca_inventory.log" 2>&1

# Count unique fingerprints (just the SHA-256 hex part) across keychains.
UNIQ_FPS=$(grep -i 'fingerprint' "$OUT_DIR/L3_ca_inventory.log" \
  | awk -F= '{print $2}' | tr -d ' ' | sort -u | sed '/^$/d' | wc -l | tr -d ' ')
TOTAL_CAS=$(grep -c 'cert [0-9]' "$OUT_DIR/L3_ca_inventory.log")

if [ "$UNIQ_FPS" -gt 1 ]; then
  record L3pre FAIL "MULTIPLE distinct mitmproxy CAs across keychains ($UNIQ_FPS unique fp, $TOTAL_CAS entries) — STALE CACHE; uninstall + reinstall to purge"
elif [ "$TOTAL_CAS" -gt 1 ]; then
  record L3pre WARN "$TOTAL_CAS mitmproxy CA entries (same fp, multiple keychains) — usually fine but unexpected"
elif [ "$TOTAL_CAS" = "0" ]; then
  record L3pre FAIL "no mitmproxy CA found in any keychain — install never landed"
else
  record L3pre PASS "exactly 1 mitmproxy CA across all keychains"
fi

if [ -f "$CA_DISK" ]; then
  DISK_FP=$(openssl x509 -in "$CA_DISK" -noout -fingerprint -sha256 2>/dev/null \
    | cut -d= -f2 | tr -d ': ' | tr 'a-f' 'A-F')
  echo "$CA_DISK fingerprint: $DISK_FP" > "$OUT_DIR/L3_cert_chain.log"
  echo "ls -la $CA_DISK:" >> "$OUT_DIR/L3_cert_chain.log"
  ls -la "$CA_DISK" >> "$OUT_DIR/L3_cert_chain.log"
  record L3a PASS "disk CA present @ $CA_DISK (fp ${DISK_FP:0:23}…)"
else
  record L3a FAIL "$CA_DISK missing — install-mac.sh didn't complete cert copy"
fi

if [ -f "$CA_BUNDLE" ]; then
  COMBINED_SIZE=$(wc -c < "$CA_BUNDLE" | tr -d ' ')
  echo "" >> "$OUT_DIR/L3_cert_chain.log"
  echo "$CA_BUNDLE size: $COMBINED_SIZE bytes" >> "$OUT_DIR/L3_cert_chain.log"
  CERT_COUNT=$(grep -c 'BEGIN CERTIFICATE' "$CA_BUNDLE" 2>/dev/null)
  if [ "$COMBINED_SIZE" -gt 50000 ] && [ "$CERT_COUNT" -gt 50 ]; then
    record L3b PASS "combined bundle has $CERT_COUNT certs ($COMBINED_SIZE bytes — system roots + mitm CA)"
  else
    record L3b FAIL "combined bundle thin: $CERT_COUNT certs / $COMBINED_SIZE bytes — passthrough HTTPS will fail for tools using REQUESTS_CA_BUNDLE"
  fi
else
  record L3b FAIL "$CA_BUNDLE missing — REQUESTS_CA_BUNDLE / SSL_CERT_FILE env vars point to nothing"
fi

# Container's actual CA being served
KC_FP_RAW=$(sudo -n security find-certificate -c mitmproxy -p /Library/Keychains/System.keychain 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ': ' | tr 'a-f' 'A-F')
if [ -z "$KC_FP_RAW" ]; then
  # try without sudo
  KC_FP_RAW=$(security find-certificate -c mitmproxy -p /Library/Keychains/System.keychain 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ': ' | tr 'a-f' 'A-F')
fi
KC_FP="$KC_FP_RAW"
if [ -n "$KC_FP" ]; then
  echo "" >> "$OUT_DIR/L3_cert_chain.log"
  echo "System keychain mitmproxy CA fingerprint: $KC_FP" >> "$OUT_DIR/L3_cert_chain.log"
  record L3c PASS "System keychain has mitmproxy CA (fp ${KC_FP:0:23}…)"
else
  record L3c FAIL "System keychain has NO mitmproxy CA — every TLS handshake will reject"
fi

CTR_FP=$(docker exec warden-proxy openssl x509 \
  -in /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem \
  -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ': ' | tr 'a-f' 'A-F')
if [ -n "$CTR_FP" ]; then
  echo "" >> "$OUT_DIR/L3_cert_chain.log"
  echo "Container mitmproxy CA fingerprint: $CTR_FP" >> "$OUT_DIR/L3_cert_chain.log"
  record L3d PASS "container CA fingerprint readable (fp ${CTR_FP:0:23}…)"
else
  record L3d FAIL "couldn't read container CA — proxy may be down"
fi

# Match check
if [ -n "$DISK_FP" ] && [ -n "$KC_FP" ] && [ -n "$CTR_FP" ]; then
  if [ "$DISK_FP" = "$KC_FP" ] && [ "$KC_FP" = "$CTR_FP" ]; then
    record L3e PASS "ALL THREE fingerprints match — trust chain is consistent"
  else
    {
      echo ""
      echo "FINGERPRINT MISMATCH:"
      echo "  disk:      $DISK_FP"
      echo "  keychain:  $KC_FP"
      echo "  container: $CTR_FP"
    } >> "$OUT_DIR/L3_cert_chain.log"
    record L3e FAIL "fingerprints DIFFER (disk/kc/ctr) — uninstall + reinstall to resync"
  fi
else
  record L3e SKIP "can't compare — one or more fingerprints missing"
fi

# Trust-evaluator check (the path Apple Secure Transport uses)
run_to 5 L3_verify_cert security verify-cert -c "$CA_DISK" -p ssl
if grep -qi 'successful' "$OUT_DIR/L3_verify_cert.log" 2>/dev/null; then
  record L3f PASS "Apple Secure Transport accepts the CA (security verify-cert -p ssl)"
else
  record L3f FAIL "security verify-cert -p ssl REJECTED — browsers/Safari will reject too. Run: sudo killall trustd; sleep 2; retry"
fi

# ── Start mitmdump live capture for the next probes ───────────────────────
section "L4-L7  starting live mitmdump capture during host probes"
docker logs -f --since 1s warden-proxy >"$MITM_LOG" 2>&1 &
MITM_PID=$!
sleep 1
echo "live mitmdump log → $MITM_LOG (pid=$MITM_PID)" >> "$SUMMARY"

# ── L4: Host → proxy → MITM host (api.anthropic.com) ──────────────────────
section "L4  host → proxy → MITM host (api.anthropic.com)"

# (a) without --cacert: relies entirely on macOS System keychain trust path
run_to 15 L4a_no_cacert /usr/bin/curl -v --max-time 12 \
  -x http://127.0.0.1:8080 \
  -o /dev/null -w "\nHTTP_CODE=%{http_code}\nTIME=%{time_total}\n" \
  -H "Authorization: Bearer sk-fake-trace-token" \
  https://api.anthropic.com/v1/models
L4a_CODE=$(grep '^HTTP_CODE=' "$OUT_DIR/L4a_no_cacert.log" 2>/dev/null | tail -1 | cut -d= -f2)
L4a_ISSUER=$(grep -i 'issuer:' "$OUT_DIR/L4a_no_cacert.log" 2>/dev/null | head -1)

case "$L4a_CODE" in
  4??|2??|5??)
    if echo "$L4a_ISSUER" | grep -qi 'mitmproxy'; then
      record L4a PASS "MITM cert accepted by system trust (HTTP $L4a_CODE, issuer=mitmproxy)"
    else
      record L4a WARN "HTTP $L4a_CODE but issuer line: $L4a_ISSUER"
    fi ;;
  '')
    if grep -qiE 'SSL_ERROR|ssl handshake|certificate problem|verify failed|self-signed' "$OUT_DIR/L4a_no_cacert.log"; then
      record L4a FAIL "TLS REJECTED by system trust — keychain CA isn't being honored. trustd cache stale? sudo killall trustd"
    elif grep -qiE 'timed out|operation timed out|connection refused|connection reset' "$OUT_DIR/L4a_no_cacert.log"; then
      record L4a FAIL "timeout/refused — proxy not forwarding OR upstream unreachable from container"
    else
      record L4a FAIL "no HTTP code — see L4a_no_cacert.log"
    fi ;;
esac

# (b) with --cacert: bypasses system trust, uses our combined bundle
run_to 15 L4b_with_cacert /usr/bin/curl -v --max-time 12 --cacert "$CA_BUNDLE" \
  -x http://127.0.0.1:8080 \
  -o /dev/null -w "\nHTTP_CODE=%{http_code}\nTIME=%{time_total}\n" \
  -H "Authorization: Bearer sk-fake-trace-token" \
  https://api.anthropic.com/v1/models
L4b_CODE=$(grep '^HTTP_CODE=' "$OUT_DIR/L4b_with_cacert.log" 2>/dev/null | tail -1 | cut -d= -f2)
case "$L4b_CODE" in
  4??|2??|5??)
    record L4b PASS "MITM cert verifies with --cacert (HTTP $L4b_CODE) — chain is valid"
    ;;
  '')
    if grep -qiE 'timed out|connection refused|reset' "$OUT_DIR/L4b_with_cacert.log"; then
      record L4b FAIL "timeout even with --cacert — proxy → upstream leg broken"
    elif grep -qiE 'verify failed|self-signed|ssl_error' "$OUT_DIR/L4b_with_cacert.log"; then
      record L4b FAIL "even our own bundle rejected — bundle/proxy fingerprint mismatch"
    else
      record L4b FAIL "no HTTP code — see L4b_with_cacert.log"
    fi ;;
esac

# ── L5: Host → proxy → passthrough host (mail.google.com) ─────────────────
section "L5  host → proxy → passthrough host (mail.google.com)"

run_to 15 L5_passthrough_mail /usr/bin/curl -v --max-time 12 \
  -x http://127.0.0.1:8080 \
  -o /dev/null -w "\nHTTP_CODE=%{http_code}\nTIME=%{time_total}\n" \
  https://mail.google.com/
L5_CODE=$(grep '^HTTP_CODE=' "$OUT_DIR/L5_passthrough_mail.log" 2>/dev/null | tail -1 | cut -d= -f2)
L5_ISSUER=$(grep -i 'issuer:' "$OUT_DIR/L5_passthrough_mail.log" 2>/dev/null | head -1)

if [ -n "$L5_CODE" ] && [ "$L5_CODE" != "000" ]; then
  if echo "$L5_ISSUER" | grep -qi 'mitmproxy'; then
    record L5a FAIL "passthrough host got mitmproxy cert (HTTP $L5_CODE) — allow_hosts regex broken, EVERYTHING is being MITM'd"
  elif echo "$L5_ISSUER" | grep -qiE 'gts|google|trust services'; then
    record L5a PASS "passthrough working (HTTP $L5_CODE, real Google issuer)"
  else
    record L5a WARN "HTTP $L5_CODE but issuer unclear: $L5_ISSUER"
  fi
else
  if grep -qiE 'timed out|connection refused|reset' "$OUT_DIR/L5_passthrough_mail.log"; then
    record L5a FAIL "passthrough timed out — proxy isn't tunneling CONNECT to upstream (MTU? container egress?)"
  else
    record L5a FAIL "no HTTP code — see L5_passthrough_mail.log"
  fi
fi

run_to 15 L5_passthrough_www /usr/bin/curl -v --max-time 10 \
  -x http://127.0.0.1:8080 \
  -o /dev/null -w "\nHTTP_CODE=%{http_code}\n" \
  https://www.google.com/
L5b_CODE=$(grep '^HTTP_CODE=' "$OUT_DIR/L5_passthrough_www.log" 2>/dev/null | tail -1 | cut -d= -f2)
if [ -n "$L5b_CODE" ] && [ "$L5b_CODE" != "000" ]; then
  record L5b PASS "www.google.com passthrough HTTP $L5b_CODE"
else
  record L5b FAIL "www.google.com passthrough also failing — confirms generic forwarding break"
fi

# ── L6: Container → upstream (egress sanity, MTU still working?) ─────────
section "L6  container → upstream raw"
run_to 15 L6_ctr_anth docker exec warden-proxy sh -c '
  echo "-- TCP connect --"
  ( timeout 5 sh -c "echo > /dev/tcp/api.anthropic.com/443" 2>&1 && echo "TCP OK" ) || echo "TCP FAIL"
  echo "-- TLS handshake --"
  echo "" | timeout 8 openssl s_client -connect api.anthropic.com:443 -servername api.anthropic.com -brief 2>&1 | head -10
'
if grep -q 'CONNECTION ESTABLISHED' "$OUT_DIR/L6_ctr_anth.log"; then
  record L6a PASS "container → api.anthropic.com:443 TLS established (egress + MTU healthy)"
elif grep -q 'TCP OK' "$OUT_DIR/L6_ctr_anth.log"; then
  record L6a FAIL "container TCP works but TLS hangs — MTU still wrong; try 1280"
else
  record L6a FAIL "container can't even open TCP to api.anthropic.com — DNS or egress dead"
fi

run_to 15 L6_ctr_gmail docker exec warden-proxy sh -c '
  echo "" | timeout 8 openssl s_client -connect mail.google.com:443 -servername mail.google.com -brief 2>&1 | head -10
'
if grep -q 'CONNECTION ESTABLISHED' "$OUT_DIR/L6_ctr_gmail.log"; then
  record L6b PASS "container → mail.google.com:443 TLS established"
else
  record L6b FAIL "container → mail.google.com TLS hangs — MTU drop to 1280 candidate"
fi

# ── L6.5: Vendor differential — same probe across multiple sites ─────────
# Symptom user reported initially: "Telegram works, Google/Gmail don't".
# Telegram desktop bypasses macOS system proxy (uses its own MTProto +
# in-app proxy config), so it's NOT a useful signal. Real test = run the
# SAME probe via curl through the proxy across vendors and see if it's
# uniformly broken (= chain/forwarding) or selectively (= HSTS/QUIC/cert
# pinning issue).
section "L6.5  vendor differential through the proxy"
for site in www.linkedin.com www.google.com mail.google.com api.anthropic.com claude.ai chatgpt.com www.cloudflare.com; do
  base="L65_$(echo "$site" | tr './:' '___')"
  /usr/bin/curl -sS --max-time 10 -x http://127.0.0.1:8080 \
    -o /dev/null -w "%{http_code} %{time_total}s issuer=%{certs}\n" \
    "https://$site/" > "$OUT_DIR/$base.log" 2>&1
  CODE=$(awk '{print $1}' "$OUT_DIR/$base.log")
  TIME=$(awk '{print $2}' "$OUT_DIR/$base.log")
  if [ "$CODE" = "000" ] || [ -z "$CODE" ]; then
    record "L65 $site" FAIL "no HTTP response ($TIME)"
  else
    record "L65 $site" PASS "HTTP $CODE in $TIME"
  fi
done

# ── L6.6: HTTP/3 / QUIC reality — does Chrome have a UDP escape hatch? ────
section "L6.6  HTTP/3 / QUIC + Alt-Svc"
run_to 8 L66_udp /usr/bin/nc -u -v -w 5 mail.google.com 443
if grep -qi 'open\|succeeded\|received' "$OUT_DIR/L66_udp.log"; then
  record L66a WARN "UDP/443 to mail.google.com appears reachable — Chrome may race QUIC and bypass proxy entirely"
else
  record L66a PASS "UDP/443 not reachable — Chrome will fall back to TCP+HTTP/2 through proxy"
fi

# ── L7: Direct probe (env-stripped) — host network sanity ─────────────────
section "L7  direct probe (proxy bypassed) — host network sanity"
run_to 12 L7_direct env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY \
  -u http_proxy -u https_proxy -u all_proxy \
  /usr/bin/curl -v --max-time 8 --noproxy '*' \
  -o /dev/null -w "\nHTTP_CODE=%{http_code}\n" \
  https://www.google.com/
L7_CODE=$(grep '^HTTP_CODE=' "$OUT_DIR/L7_direct.log" 2>/dev/null | tail -1 | cut -d= -f2)
if [ -n "$L7_CODE" ] && [ "$L7_CODE" != "000" ]; then
  record L7 PASS "host can reach internet directly (HTTP $L7_CODE) — break is in proxy path"
else
  record L7 FAIL "host can't reach internet even bypassing proxy — host-level network broken"
fi

# ── Stop the mitmdump tail and slice it ───────────────────────────────────
sleep 2
kill "$MITM_PID" 2>/dev/null
wait "$MITM_PID" 2>/dev/null

section "L8  mitmdump live log slice (during probes)"
{
  echo "-- handshake/TLS errors --"
  grep -iE 'handshake|tls|ssl|certificate' "$MITM_LOG" | tail -50
  echo ""
  echo "-- addon errors / tracebacks --"
  grep -iE 'error|exception|traceback|failed' "$MITM_LOG" | tail -50
  echo ""
  echo "-- per-host activity --"
  grep -iE 'api\.anthropic\.com|mail\.google\.com|www\.google\.com|claude\.ai' "$MITM_LOG" | tail -80
} > "$OUT_DIR/L8_mitm_slice.log"

ERRCOUNT=$(grep -ciE 'handshake failed|tls.*error|ssl.*error|traceback' "$MITM_LOG" 2>/dev/null)
if [ "$ERRCOUNT" -gt 0 ]; then
  record L8 WARN "$ERRCOUNT TLS/handshake/error lines in mitmdump during probes — see L8_mitm_slice.log"
else
  record L8 PASS "no fatal mitmdump errors during probes"
fi

# ── Verdict ───────────────────────────────────────────────────────────────
section "VERDICT"
{
  echo ""
  echo "================================================================="
  echo "                    LAYER-BY-LAYER RESULTS"
  echo "================================================================="
  printf "%-6s %-5s %s\n" LAYER STATUS NOTE
  echo "-----------------------------------------------------------------"
  for r in "${RESULTS[@]}"; do
    L=$(echo "$r" | cut -d'|' -f1)
    S=$(echo "$r" | cut -d'|' -f2)
    N=$(echo "$r" | cut -d'|' -f3)
    printf "%-6s %-5s %s\n" "$L" "$S" "$N"
  done
  echo ""
} | tee -a "$SUMMARY"

# Decide root cause hint
ROOT_CAUSE=""
for r in "${RESULTS[@]}"; do
  S=$(echo "$r" | cut -d'|' -f2)
  L=$(echo "$r" | cut -d'|' -f1)
  if [ "$S" = "FAIL" ]; then
    ROOT_CAUSE="${ROOT_CAUSE}${L} "
  fi
done

{
  echo "================================================================="
  echo "                       ROOT-CAUSE HINT"
  echo "================================================================="
  if [ -z "$ROOT_CAUSE" ]; then
    echo "No FAILs detected. If browsers still break, look at L8 errors and"
    echo "check chrome://net-internals or quit/reopen the browser."
  else
    echo "Failed layers: $ROOT_CAUSE"
    echo ""
    case "$ROOT_CAUSE" in
      *L0*) echo "→ Containers/MTU broken first — fix L0 before anything else." ;;
      *L1*) echo "→ System proxy not pointed at warden — re-run install-mac.sh." ;;
      *L2*) echo "→ Proxy not reachable on 127.0.0.1:8080 — container down or port mapped wrong." ;;
      *L3*) echo "→ Cert chain inconsistent across disk/keychain/container — uninstall + reinstall." ;;
      *L4a*L4b*) echo "→ Both --cacert and system trust fail on MITM host — proxy → upstream leg dead." ;;
      *L4a*) echo "→ System trust path failing for MITM host but --cacert works → trustd cache stale: sudo killall trustd; reopen browser." ;;
      *L5*) echo "→ Passthrough host failing → CONNECT tunneling broken (MTU? allow_hosts regex too greedy?)." ;;
      *L6*) echo "→ Container → upstream broken → MTU still wrong, drop bridge MTU to 1280 in compose and 'docker compose down && up -d'." ;;
      *L7*) echo "→ Host has no internet even bypassing proxy — Wi-Fi / DNS / VPN issue, NOT warden." ;;
    esac
  fi
  echo ""
  echo "All raw logs in: $OUT_DIR/"
} | tee -a "$SUMMARY"

printf "\n${C_BOLD}done${C_END} → ${C_INFO}%s/SUMMARY.txt${C_END}\n" "$OUT_DIR"
