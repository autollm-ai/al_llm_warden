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
    echo "[entrypoint] starting mitmdump on 0.0.0.0:8080"
    exec mitmdump \
      -s /app/proxy/addon.py \
      --listen-host 0.0.0.0 \
      --listen-port 8080 \
      --set "block_global=false"
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
