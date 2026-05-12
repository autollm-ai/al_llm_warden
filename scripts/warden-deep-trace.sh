#!/usr/bin/env bash
# warden-deep-trace.sh — full-stack instrumentation run.
#
# Difference vs warden-trace.sh:
#   • Restarts warden-proxy with WARDEN_DEEP_TRACE=1 so the container
#     captures eth0 traffic, dumps a JSON event log, and snapshots
#     sockets every 5s.
#   • Also runs HOST-side tcpdump on lo0 (proxy traffic) + the active
#     interface (egress) for the duration of the probes.
#   • Runs proxy-path probes for several hosts CONCURRENTLY (mitmproxy
#     pool behavior under load is part of the symptom).
#   • Bundles every artifact — host pcaps, container pcap, addon JSONL,
#     mitmdump verbose log, socket snapshots, system state — into one
#     directory so we can correlate by timestamp.
#
# Usage:
#   sudo bash scripts/warden-deep-trace.sh         # sudo for tcpdump
#
# Output:
#   warden-deep-trace-<timestamp>/
#     host_lo0.pcap, host_en.pcap     — host-side captures
#     container_eth0.pcap             — copied from container
#     deep-trace.jsonl                — mitmproxy debug-addon events
#     mitmdump.log                    — verbose mitmdump container log
#     sockets.log                     — periodic ss/FD snapshots
#     state/*.txt                     — host state snapshots
#     probes/*.log                    — per-probe curl -v output

set +e
shopt -s nullglob 2>/dev/null

if [ "$(id -u)" != "0" ]; then
  echo "warden-deep-trace.sh needs sudo (tcpdump on host interfaces)." >&2
  echo "Re-run: sudo bash scripts/warden-deep-trace.sh" >&2
  exit 1
fi

TS=$(date +%Y%m%d-%H%M%S)
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/warden-deep-trace-$TS"
mkdir -p "$OUT/state" "$OUT/probes"

# Re-shell into the user's normal shell to inherit HTTPS_PROXY etc.
USER_HOME=$(eval echo "~$SUDO_USER" 2>/dev/null || echo "$HOME")

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }

# ── 1. Snapshot host state ────────────────────────────────────────────
log "▶ snapshot host state"
{ ifconfig; echo; route -n get default; echo; netstat -nr | head -50; } > "$OUT/state/network.txt" 2>&1
scutil --proxy > "$OUT/state/scutil_proxy.txt" 2>&1
networksetup -listallnetworkservices > "$OUT/state/network_services.txt" 2>&1
sudo -u "${SUDO_USER:-$USER}" env | grep -iE 'proxy|ssl|ca_' > "$OUT/state/user_env.txt" 2>&1
pfctl -s rules > "$OUT/state/pf_rules.txt" 2>&1
docker ps --format '{{.Names}}\t{{.Status}}\t{{.Ports}}' > "$OUT/state/docker_ps.txt" 2>&1
docker network inspect al_llm_warden_warden-net > "$OUT/state/docker_network.txt" 2>&1
docker exec warden-proxy sh -c 'ip -d link show eth0 || ifconfig eth0' > "$OUT/state/container_eth0.txt" 2>&1
docker exec warden-proxy ip route > "$OUT/state/container_route.txt" 2>&1
docker exec warden-proxy cat /etc/resolv.conf > "$OUT/state/container_resolv.txt" 2>&1

# ── 2. Restart proxy with deep-trace mode ─────────────────────────────
log "▶ restart warden-proxy with WARDEN_DEEP_TRACE=1"
( cd "$ROOT" && WARDEN_DEEP_TRACE=1 docker compose up -d warden-proxy ) >> "$OUT/run.log" 2>&1
# Wait for healthy.
for i in $(seq 1 30); do
  if docker exec warden-proxy ls /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem >/dev/null 2>&1; then
    log "  proxy healthy after ${i}s"; break
  fi
  sleep 1
done
# Wipe previous artifacts inside container so this run is clean.
docker exec warden-proxy sh -c 'rm -f /data/warden-deep-trace.jsonl /data/warden-cap.pcap* /data/warden-sockets.log /data/warden-tcpdump.log' >/dev/null 2>&1
# Restart once more so tcpdump starts with empty files.
( cd "$ROOT" && WARDEN_DEEP_TRACE=1 docker compose restart warden-proxy ) >> "$OUT/run.log" 2>&1
sleep 4

# ── 3. Start host-side tcpdump on lo0 + active interface ──────────────
ACTIVE_IF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' | head -1)
log "▶ start host tcpdump (lo0 + $ACTIVE_IF)"
tcpdump -i lo0 -nn -s 0 -w "$OUT/host_lo0.pcap" \
  '(tcp port 8080) or (tcp port 8090)' >/dev/null 2>&1 &
LO_PID=$!
tcpdump -i "$ACTIVE_IF" -nn -s 0 -w "$OUT/host_${ACTIVE_IF}.pcap" \
  '(tcp port 443 or tcp port 80) and not (host 127.0.0.1)' >/dev/null 2>&1 &
EN_PID=$!
sleep 1   # let captures actually open

# Also stream container's mitmdump log live.
( docker logs -f --since 1s warden-proxy >"$OUT/mitmdump.log" 2>&1 ) &
MITM_PID=$!
sleep 1

# ── 4. Concurrent probes (the realistic load — multiple flows at once) ─
log "▶ run probes concurrently"
PROBE_HOSTS=(
  "https://api.anthropic.com/v1/models"   # MITM (real user pain)
  "https://claude.ai/"                    # MITM
  "https://chatgpt.com/"                  # MITM
  "https://www.google.com/"               # passthrough
  "https://mail.google.com/"              # passthrough
  "https://www.linkedin.com/"             # passthrough (was ok before — control)
  "http://example.com/"                   # plain HTTP, no TLS
)
PROXY="http://127.0.0.1:8080"

# Run as the invoking user so HTTPS_PROXY / cert env vars match.
RUN_AS="${SUDO_USER:-$USER}"
for url in "${PROBE_HOSTS[@]}"; do
  base="probe_$(echo "$url" | tr '/:?#&=.' '_______' | tr -s '_' | cut -c1-60)"
  ( sudo -u "$RUN_AS" /usr/bin/curl -v --max-time 15 -x "$PROXY" \
      -o /dev/null -w "\nHTTP_CODE=%{http_code}\nTIME=%{time_total}\nDNS=%{time_namelookup}\nCONNECT=%{time_connect}\nAPPCONNECT=%{time_appconnect}\nPRETRANSFER=%{time_pretransfer}\nSTARTTRANSFER=%{time_starttransfer}\n" \
      "$url" ) > "$OUT/probes/${base}.log" 2>&1 &
done
# Direct (no proxy) controls — same hosts, env-stripped.
for url in "https://api.anthropic.com/v1/models" "https://www.google.com/"; do
  base="direct_$(echo "$url" | tr '/:?#&=.' '_______' | tr -s '_' | cut -c1-60)"
  ( sudo -u "$RUN_AS" env -u HTTPS_PROXY -u HTTP_PROXY -u ALL_PROXY \
      /usr/bin/curl -v --max-time 10 --noproxy '*' \
      -o /dev/null -w "\nHTTP_CODE=%{http_code}\nTIME=%{time_total}\n" \
      "$url" ) > "$OUT/probes/${base}.log" 2>&1 &
done
# Container-side direct probe — proves egress without mitmproxy.
( docker exec warden-proxy sh -c '
    for u in https://api.anthropic.com/v1/models https://www.google.com/; do
      echo "== $u =="
      curl -v --max-time 10 -o /dev/null \
        -w "HTTP_CODE=%{http_code} TIME=%{time_total}\n" "$u" 2>&1
    done
  ' ) > "$OUT/probes/container_direct.log" 2>&1 &

# Wait for all probes (max ~16s total).
wait
log "▶ probes done"

# ── 5. Stop captures, pull container artifacts ────────────────────────
sleep 2
kill "$LO_PID" "$EN_PID" "$MITM_PID" 2>/dev/null
wait "$LO_PID" "$EN_PID" "$MITM_PID" 2>/dev/null

log "▶ pull container artifacts"
docker cp warden-proxy:/data/warden-deep-trace.jsonl  "$OUT/deep-trace.jsonl"  2>>"$OUT/run.log"
docker cp warden-proxy:/data/warden-sockets.log       "$OUT/sockets.log"       2>>"$OUT/run.log"
docker cp warden-proxy:/data/warden-tcpdump.log       "$OUT/tcpdump.log"       2>>"$OUT/run.log"
# Pcap may be split into rotation files — copy whichever exist.
for f in $(docker exec warden-proxy sh -c 'ls /data/warden-cap.pcap* 2>/dev/null'); do
  base=$(basename "$f")
  docker cp "warden-proxy:$f" "$OUT/container_${base}" 2>>"$OUT/run.log"
done

# ── 6. Quick correlation summary ──────────────────────────────────────
log "▶ correlate"
{
  echo "============================================================"
  echo "  PROBE OUTCOMES"
  echo "============================================================"
  for f in "$OUT/probes/"*.log; do
    name=$(basename "$f" .log)
    code=$(grep '^HTTP_CODE=' "$f" | tail -1 | cut -d= -f2)
    time=$(grep '^TIME=' "$f" | tail -1 | cut -d= -f2)
    err=$(grep -iE 'curl: \(' "$f" | head -1)
    printf '  %-60s code=%s time=%s %s\n' "$name" "${code:-???}" "${time:-?}" "$err"
  done
  echo
  echo "============================================================"
  echo "  DEEP-TRACE EVENTS BY TYPE (from debug_addon)"
  echo "============================================================"
  if [ -s "$OUT/deep-trace.jsonl" ]; then
    awk -F'"ev":"' 'NF>1 {split($2, a, "\""); print a[1]}' "$OUT/deep-trace.jsonl" | sort | uniq -c | sort -rn
  else
    echo "  (no events — debug addon didn't load? check mitmdump.log)"
  fi
  echo
  echo "============================================================"
  echo "  TLS FAILURES IN MITMDUMP LOG"
  echo "============================================================"
  grep -iE 'tls|handshake|verify|cert' "$OUT/mitmdump.log" | tail -50
  echo
  echo "============================================================"
  echo "  ADDON / FLOW ERRORS"
  echo "============================================================"
  grep -iE 'error|exception|traceback|hook' "$OUT/mitmdump.log" | tail -30
  echo
  echo "============================================================"
  echo "  SOCKET SNAPSHOTS — peak counts"
  echo "============================================================"
  grep -E 'TCP:|estab|FD count' "$OUT/sockets.log" 2>/dev/null | tail -30
} > "$OUT/SUMMARY.txt"

# Make output readable by user.
chown -R "${SUDO_USER:-$USER}:staff" "$OUT" 2>/dev/null

log "▶ done → $OUT/SUMMARY.txt"
log "  Wireshark: open host_lo0.pcap / host_${ACTIVE_IF}.pcap / container_*.pcap"
log "  Filter for one flow: jq 'select(.cid==\"<id>\")' deep-trace.jsonl"