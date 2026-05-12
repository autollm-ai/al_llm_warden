FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    WARDEN_DB=/data/warden.db \
    WARDEN_MODEL_DIR=/models \
    WARDEN_FRONTEND_DIR=/app/frontend

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl ca-certificates tini \
        tcpdump iproute2 procps lsof dnsutils \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Make Python / certifi use the system CA bundle instead of the wheel's
# bundled (potentially stale) one. Lets mitmproxy verify upstream certs
# against current Mozilla roots.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

WORKDIR /app

# requirements.txt first → cached layer for the torch wheel.
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --extra-index-url https://download.pytorch.org/whl/cpu \
        -r /tmp/requirements.txt

COPY backend/warden    /app/warden
COPY backend/proxy     /app/proxy
COPY backend/api       /app/api
COPY backend/training  /app/training
COPY backend/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

COPY frontend          /app/frontend

# Pre-trained weights, if committed to the repo. On first `docker compose
# up`, Docker seeds the empty `warden-models` named volume from /models in
# the image — so end users get a working model instantly and the autotrain
# branch in entrypoint.sh is skipped.  Failing this COPY is fine (the *
# glob won't error if files are absent), it just means autotrain runs.
COPY models/ /models/

VOLUME ["/data", "/models"]

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
