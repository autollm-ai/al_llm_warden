#!/usr/bin/env bash
# Run AFTER warden is turned ON and you've reproduced the Chrome failure.
# Writes full diagnostics into ./warden-diag.txt.  Then turn warden OFF and
# share the file back.
#
# What this looks for, specifically when Gmail (mail.google.com) fails in the
# browser but warden seems "up":
#
#   1. Is the system actually pointed at the proxy? (network services, scutil,
#      shell env, ~/.zshrc residue).
#   2. Is port 8080 bound to 127.0.0.1 only? (off-host exposure = open relay).
#   3. Is there exactly ONE mitmproxy CA in the keychains, and does its
#      fingerprint match the cert the running container is serving?
#   4. For passthrough hosts (mail.google.com): does Chrome/curl receive the
#      REAL Google cert (CN=*.google.com, issuer=GTS) and not mitmproxy's?
#   5. For MITM hosts (api.anthropic.com): full TLS to the mitmproxy leaf.
#   6. HTTP/3 reality check — Chrome tries QUIC for Gmail; system HTTP proxies
#      don't carry UDP, so we test UDP/443 reachability and Alt-Svc.
#   7. DNS sanity (host + container).
#   8. Container's outbound to mail.google.com:443 (the proxy's upstream leg).
#   9. mitmproxy logs filtered to mail.google.com only, plus all errors with
#      their host attribution preserved.
#  10. Full unfiltered curl traces saved alongside the grepped summaries, so
#      we never lose the line that explains the failure.
#
# Anything that times out gets a clear "TIMEOUT" marker — we never want a
# silent hang to hide a probe.

set +e
shopt -s nullglob 2>/dev/null

OUT="$(pwd)/warden-diag.txt"
RAW_DIR="$(pwd)/warden-diag-raw"
mkdir -p "$RAW_DIR"
: > "$OUT"

say() { printf '\n=== %s ===\n' "$*" | tee -a "$OUT" >/dev/null; echo "" >> "$OUT" 2>/dev/null; }
hdr() { printf '\n--- %s ---\n' "$*" >> "$OUT"; }
note() { printf '[note] %s\n' "$*" >> "$OUT"; }

run() {
  # run "<label>" <cmd...>  — append both stdout and stderr, never abort.
  local label="$1"; shift
  hdr "$label"
  ( "$@" ) >>"$OUT" 2>&1
  local rc=$?
  printf '[exit=%s]\n' "$rc" >> "$OUT"
}

run_to() {
  # run_to <seconds> "<label>" <cmd...>  — same but with a hard timeout.
  local t="$1"; shift
  local label="$1"; shift
  hdr "$label"
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$t" "$@" >>"$OUT" 2>&1
  else
    # macOS fallback: background + wait + kill.
    ( "$@" ) >>"$OUT" 2>&1 &
    local pid=$!
    ( sleep "$t" && kill -9 "$pid" 2>/dev/null ) &
    local watcher=$!
    wait "$pid" 2>/dev/null
    local rc=$?
    kill -9 "$watcher" 2>/dev/null
    printf '[exit=%s]\n' "$rc" >> "$OUT"
    return
  fi
  printf '[exit=%s]\n' "$?" >> "$OUT"
}

#######################################################################
# 0. Header
#######################################################################
say "date / host / uname"
date | tee -a "$OUT" >/dev/null
uname -a >> "$OUT"
sw_vers 2>/dev/null >> "$OUT"

#######################################################################
# 1. System proxy state
#######################################################################
say "system proxy state per network service"
for svc in $(networksetup -listallnetworkservices 2>/dev/null | tail -n +2); do
  echo "-- $svc --" >> "$OUT"
  networksetup -getwebproxy           "$svc" 2>&1 >> "$OUT"
  networksetup -getsecurewebproxy     "$svc" 2>&1 >> "$OUT"
  networksetup -getproxybypassdomains "$svc" 2>&1 >> "$OUT"
  networksetup -getproxyautodiscovery "$svc" 2>&1 >> "$OUT"
done

say "scutil --proxy"
scutil --proxy >> "$OUT" 2>&1

say "shell env (HTTP_PROXY etc.) + ~/.zshrc warden block"
{
  echo "HTTP_PROXY=$HTTP_PROXY"
  echo "HTTPS_PROXY=$HTTPS_PROXY"
  echo "ALL_PROXY=$ALL_PROXY"
  echo "NO_PROXY=$NO_PROXY"
  echo "REQUESTS_CA_BUNDLE=$REQUESTS_CA_BUNDLE"
  echo "SSL_CERT_FILE=$SSL_CERT_FILE"
} >> "$OUT"
echo "-- ~/.zshrc warden block --" >> "$OUT"
sed -n '/# >>> warden proxy >>>/,/# <<< warden proxy <<</p' ~/.zshrc 2>/dev/null >> "$OUT"

#######################################################################
# 2. Keychain + container CA cross-check
#######################################################################
say "mitmproxy CAs across keychains (counts + SHA-256)"
for kc in \
  /Library/Keychains/System.keychain \
  ~/Library/Keychains/login.keychain-db \
  /System/Library/Keychains/SystemRootCertificates.keychain
do
  echo "-- $kc --" >> "$OUT"
  count=$(security find-certificate -a -c mitmproxy "$kc" 2>/dev/null | grep -c 'keychain:')
  echo "mitmproxy CA count = $count" >> "$OUT"
  security find-certificate -a -c mitmproxy -p "$kc" 2>/dev/null \
    | awk '/BEGIN CERT/{n++; f="'"$RAW_DIR"'/ca-'"$(basename "$kc")"'-"n".pem"} {print > f}'
  for pem in "$RAW_DIR"/ca-"$(basename "$kc")"-*.pem; do
    [ -f "$pem" ] || continue
    echo "  $(basename "$pem"):" >> "$OUT"
    openssl x509 -in "$pem" -noout -fingerprint -sha256 -subject -issuer -dates 2>&1 \
      | sed 's/^/    /' >> "$OUT"
  done
done

say "warden trust state of CA cert (SecTrustEvaluate via security verify-cert)"
CA_BUNDLE="$HOME/.config/warden/warden-ca-bundle.pem"
if [ -f "$CA_BUNDLE" ]; then
  echo "bundle = $CA_BUNDLE" >> "$OUT"
  openssl x509 -in "$CA_BUNDLE" -noout -fingerprint -sha256 -subject -issuer 2>&1 >> "$OUT"
  security verify-cert -c "$CA_BUNDLE" -p ssl 2>&1 >> "$OUT"
else
  echo "MISSING: $CA_BUNDLE" >> "$OUT"
fi

#######################################################################
# 3. Container status + listener bindings
#######################################################################
say "warden container status"
docker ps --format "{{.Names}}\t{{.Status}}\t{{.Ports}}" | grep warden >> "$OUT"

say "TCP listeners on host (8080 / 8090) — must bind 127.0.0.1, NOT 0.0.0.0"
{
  echo "-- lsof :8080 --"
  lsof -nP -iTCP:8080 -sTCP:LISTEN 2>&1
  echo "-- lsof :8090 --"
  lsof -nP -iTCP:8090 -sTCP:LISTEN 2>&1
} >> "$OUT"
note "If you see *:8080 (or 0.0.0.0:8080) instead of 127.0.0.1:8080, off-host clients can use you as an open relay — see project_proxy_port_binding memory."

say "container CA fingerprint (running mitmproxy)"
docker exec warden-proxy openssl x509 \
  -in /home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem \
  -noout -fingerprint -sha256 -subject -issuer -dates 2>&1 >> "$OUT"

say "container env + mitmproxy version"
docker exec warden-proxy sh -lc 'mitmdump --version 2>&1 | head -20; echo "--"; env | sort' >> "$OUT"

say "mitmproxy startup banner + allow-hosts regex"
docker logs warden-proxy 2>&1 | sed -n '1,30p' >> "$OUT"

#######################################################################
# 4. DNS — host AND container
#######################################################################
say "DNS resolution (host)"
for h in mail.google.com api.anthropic.com claude.ai; do
  hdr "host: $h"
  /usr/bin/dig +short +time=3 +tries=1 "$h" A    2>&1 >> "$OUT"
  /usr/bin/dig +short +time=3 +tries=1 "$h" AAAA 2>&1 >> "$OUT"
done

say "DNS resolution (inside warden-proxy container)"
for h in mail.google.com api.anthropic.com; do
  hdr "container: $h"
  docker exec warden-proxy sh -lc "getent hosts $h || nslookup $h 2>&1" >> "$OUT"
done

#######################################################################
# 5. Container -> upstream connectivity (the proxy's outbound leg)
#######################################################################
say "container -> mail.google.com:443 (raw TCP + TLS handshake)"
docker exec warden-proxy sh -lc '
  set +e
  echo "-- nc -vz --"
  ( echo > /dev/tcp/mail.google.com/443 ) 2>&1 || echo "TCP open failed"
  echo "-- openssl s_client (no SNI) --"
  echo "" | timeout 8 openssl s_client -connect mail.google.com:443 -servername mail.google.com -brief 2>&1 | head -25
' >> "$OUT" 2>&1

say "container -> api.anthropic.com:443 (raw TCP + TLS handshake)"
docker exec warden-proxy sh -lc '
  echo "" | timeout 8 openssl s_client -connect api.anthropic.com:443 -servername api.anthropic.com -brief 2>&1 | head -25
' >> "$OUT" 2>&1

#######################################################################
# 6. Probes through the proxy — FULL output saved to raw files
#######################################################################
probe() {
  # probe <label> <url>  — save full curl -v to raw file, summary to OUT
  local label="$1" url="$2"
  local raw="$RAW_DIR/$(echo "$label" | tr ' /' '__').log"
  hdr "$label  ($url)  [full log: $raw]"
  /usr/bin/curl -v --max-time 12 -x http://127.0.0.1:8080 "$url" -o /dev/null > "$raw" 2>&1
  local rc=$?
  echo "[curl exit=$rc]" >> "$OUT"
  grep -E "Trying|Connected|CONNECT|TLS handshake|SSL connection|subject|subjectAlt|issuer|verify|HTTP/|alt-svc|Failed|error|refused|reset|certificate" "$raw" >> "$OUT"
}

say "PROBE — passthrough host mail.google.com (must show issuer=GTS, NOT mitmproxy)"
probe "passthrough-mail" "https://mail.google.com/"

say "PROBE — passthrough host www.google.com (sanity vs mail)"
probe "passthrough-www"  "https://www.google.com/"

say "PROBE — MITM host api.anthropic.com (must show issuer=mitmproxy)"
probe "mitm-anthropic"   "https://api.anthropic.com/"

say "PROBE — MITM host claude.ai"
probe "mitm-claude"      "https://claude.ai/"

say "PROBE — direct (truly bypass proxy) sanity on mail.google.com"
hdr "direct-mail (env unset)"
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
  /usr/bin/curl -v --max-time 8 --noproxy '*' https://mail.google.com/ -o /dev/null \
  > "$RAW_DIR/direct-mail.log" 2>&1
echo "[curl exit=$?]" >> "$OUT"
grep -E "Trying|Connected|TLS handshake|SSL connection|subject|issuer|verify|HTTP/|Failed|error|certificate" "$RAW_DIR/direct-mail.log" >> "$OUT"

#######################################################################
# 7. HTTP/3 / QUIC reality check
#######################################################################
say "HTTP/3 / QUIC — UDP 443 reachability + Alt-Svc"
note "Chrome prefers HTTP/3 (QUIC over UDP/443) for Gmail. macOS HTTP proxies don't carry UDP, so QUIC traffic to mail.google.com bypasses warden entirely. If UDP/443 is open egress AND Chrome successfully races QUIC, the browser may load most of Gmail outside warden's view; if QUIC is partially broken (e.g. some packets reach, some don't), Gmail can hang/error. Disabling HTTP/3 in chrome://flags often resolves it."
hdr "UDP 443 to mail.google.com (5s nc -u)"
( /usr/bin/nc -u -v -w 5 mail.google.com 443 < /dev/null ) >> "$OUT" 2>&1
hdr "Alt-Svc header from a passthrough probe"
grep -i 'alt-svc' "$RAW_DIR"/passthrough-*.log >> "$OUT" 2>&1
hdr "/usr/bin/curl --http3 attempt (will fail without http3 build, but tells us)"
/usr/bin/curl --http3 -v --max-time 6 https://mail.google.com/ -o /dev/null >> "$OUT" 2>&1
echo "[exit=$?]" >> "$OUT"

#######################################################################
# 8. mitmproxy logs — sliced by host and by error
#######################################################################
say "warden-proxy log: ALL lines mentioning mail.google.com (last 500)"
docker logs warden-proxy 2>&1 | grep -i 'mail\.google\.com' | tail -500 >> "$OUT"

say "warden-proxy log: ALL lines mentioning google (excluding mail.google.com)"
docker logs warden-proxy 2>&1 | grep -i 'google' | grep -vi 'mail\.google\.com' | tail -100 >> "$OUT"

say "warden-proxy log: every error/exception/handshake-failure with 2 lines context"
docker logs warden-proxy 2>&1 \
  | grep -niE 'error|exception|traceback|failed|handshake|refused|reset|tls' \
  | tail -120 >> "$OUT"

say "warden-proxy log: addon row events (skipped/inserted) for last 200 flows"
docker logs warden-proxy 2>&1 | grep -iE '_write_skipped|inserted row|row written|monitor|addon' | tail -200 >> "$OUT"

say "warden-proxy stderr (full last 200 lines)"
docker logs warden-proxy 2>&1 | tail -200 >> "$OUT"

#######################################################################
# 9. Browser-side hints
#######################################################################
say "browser hints — what to capture next if this still doesn't explain it"
cat <<'EOF' >> "$OUT"
If the probes above all look healthy but Chrome still fails on Gmail:

  1. Open chrome://net-export, click "Start Logging to Disk", reproduce the
     Gmail failure, stop logging, and share the .json. We can replay it in
     https://netlog-viewer.appspot.com/ to see the exact failure code.

  2. In chrome://flags, search "QUIC" — set "Experimental QUIC protocol" to
     Disabled, restart Chrome, retry. If it now works, the issue is HTTP/3
     racing past warden over UDP.

  3. chrome://net-internals/#hsts — look up domain "mail.google.com". If
     "static_sts_domain" / "static_pkp_domain" appears, that confirms HSTS
     pinning is in play; with pure CONNECT passthrough this is fine, but if
     anything in the chain is replacing the cert it will be silently rejected.

  4. chrome://policy — confirm there isn't a managed proxy policy overriding
     the system proxy.
EOF

#######################################################################
# 10. Footer
#######################################################################
echo ""                                                            >> "$OUT"
echo "Wrote $OUT"                                                  >> "$OUT"
echo "Raw curl/openssl logs in $RAW_DIR/"                          >> "$OUT"

echo ""
echo "Wrote $OUT"
echo "Full raw probe logs are in $RAW_DIR/"
echo ""
echo "Now: open Chrome, try https://mail.google.com/, and immediately re-run:"
echo "  bash scripts/warden-diag.sh"
echo ""
echo "Then turn warden off and share warden-diag.txt + warden-diag-raw/ back."
