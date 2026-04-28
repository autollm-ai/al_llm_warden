FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    WARDEN_DB=/data/warden.db \
    WARDEN_MODEL_DIR=/models \
    WARDEN_FRONTEND_DIR=/app/frontend

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates tini \
 && rm -rf /var/lib/apt/lists/*

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

VOLUME ["/data", "/models"]

ENTRYPOINT ["/usr/bin/tini", "--", "/app/entrypoint.sh"]
