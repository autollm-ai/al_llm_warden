#!/usr/bin/env bash
# Entrypoint dispatcher.
#   warden-proxy   → run mitmproxy with the warden addon
#   warden-api     → run the FastAPI dashboard / static frontend
#   warden-train   → generate data + train tokenizer + LSTM
#   sh ...         → drop into a shell

set -euo pipefail

mkdir -p /data /models

case "${1:-warden-proxy}" in
  warden-proxy)
    # Train the model in-process the first time (synchronous so the proxy
    # boots with tier-2 enabled). Skip if model files exist.
    if [ "${WARDEN_AUTOTRAIN:-1}" = "1" ] \
        && [ ! -f /models/lstm.pt -o ! -f /models/bpe.json ]; then
      echo "[entrypoint] no model found — running first-time training (a few minutes)…"
      python -m training.train \
        --n-samples "${WARDEN_TRAIN_SAMPLES:-8000}" \
        --epochs    "${WARDEN_TRAIN_EPOCHS:-4}" \
      || echo "[entrypoint] training failed — proxy will run with tier-1 only"
    fi
    # Pin the mitmproxy config dir so the CA always lands at a known path
    # regardless of which user the container is running as. The healthcheck
    # and `docker cp` instructions both assume this exact location.
    export MITM_CONFDIR=/home/mitmproxy/.mitmproxy
    mkdir -p "$MITM_CONFDIR"

    # Build an allow-list regex from warden.domains.SHADOW_AI_DOMAINS so that
    # only LLM endpoints get MITM'd. Everything else (Google services,
    # Apple/Microsoft telemetry, CDN assets) gets a transparent CONNECT
    # tunnel — fixes 502s on long-poll endpoints and dramatically reduces
    # the surface area for proxy weirdness.
    # Match each registered host AND any of its subdomains, so e.g.
    # `eu.api.openai.com` is intercepted alongside `api.openai.com`.
    # Anything not matching this regex bypasses MITM entirely (transparent
    # CONNECT tunnel) — non-shadow-AI traffic passes through as-is.
    ALLOW_HOSTS=$(python -c "
import re, sys
sys.path.insert(0, '/app')
from warden.domains import SHADOW_AI_DOMAINS
hosts = sorted(set(SHADOW_AI_DOMAINS.keys()))
parts = [r'(?:[a-z0-9-]+\.)*' + re.escape(h) for h in hosts]
print(r'^(' + '|'.join(parts) + r')(:\d+)?$')
")
    echo "[entrypoint] starting mitmdump on 0.0.0.0:8080  (confdir=$MITM_CONFDIR)"
    echo "[entrypoint] allow-hosts regex: $ALLOW_HOSTS"
    # --ssl-insecure: skip *upstream* cert verification (mitmdump → server).
    #   We are an observer, not a security boundary — when a stale CA bundle
    #   in the container can't verify Cloudflare's chain, we shouldn't break
    #   the user's traffic. The CLIENT-side TLS (browser → mitmdump) is still
    #   signed by our own CA which the user trusted explicitly.
    # --set stream_large_bodies=5m
    #   Don't blanket-stream every body. The addon's `requestheaders`
    #   hook explicitly buffers request bodies (so we can classify them)
    #   and the `responseheaders` hook explicitly streams SSE / chunked
    #   responses (so chatgpt.com / claude.ai render token-by-token).
    #   The 5m floor is just an upper bound for anything the addon
    #   doesn't override — bodies that big are almost always file uploads
    #   we'd hash-skip anyway.
    # --allow-hosts
    #   Only MITM LLM domains. Pass everything else through as plain CONNECT.
    exec mitmdump \
      -s /app/proxy/addon.py \
      --listen-host 0.0.0.0 \
      --listen-port 8080 \
      --set "confdir=$MITM_CONFDIR" \
      --set "block_global=false" \
      --set "connection_strategy=lazy" \
      --set "stream_large_bodies=5m" \
      --set "allow_hosts=$ALLOW_HOSTS" \
      --ssl-insecure
    ;;
  warden-api)
    echo "[entrypoint] starting FastAPI on 0.0.0.0:8090"
    exec uvicorn api.main:app --host 0.0.0.0 --port 8090
    ;;
  warden-train)
    shift
    exec python -m training.train "$@"
    ;;
  warden-generate)
    shift
    exec python -m training.generate_data "$@"
    ;;
  sh|bash)
    exec "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
