"""Heavy-instrumentation addon for diagnosing the warden TLS-break failure mode.

Activated only when WARDEN_DEEP_TRACE=1 (entrypoint.sh wires this in via a
second `-s` flag). Stays out of the production code path otherwise.

Every TLS / connection / HTTP lifecycle event is appended to
/data/warden-deep-trace.jsonl so we can correlate against pcaps after
the fact. Each line is one JSON object with fields:

  ts    — float seconds since epoch (host clock)
  ev    — short event name (see _EVENTS below)
  cid   — mitmproxy connection ID (links client/server-side events)
  peer  — "host:port" of the relevant peer
  sni   — TLS SNI when known
  alpn  — ALPN proposal/selection when known
  err   — short error string (if any)
  extra — small dict for event-specific fields (sizes, durations, etc.)

This file is self-contained — no warden imports — so it works in deep-trace
mode even if the main addon errors out. Reading it back: `jq` works.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any

# Where to write. /data is a docker volume so the host can pull it out
# with `docker cp warden-proxy:/data/warden-deep-trace.jsonl .`
_TRACE_PATH = os.environ.get("WARDEN_DEEP_TRACE_PATH", "/data/warden-deep-trace.jsonl")
_lock = threading.Lock()
# First-seen timestamp per connection id, so we can compute durations.
_first_seen: dict[str, float] = {}


def _emit(ev: str, **fields: Any) -> None:
    rec = {"ts": time.time(), "ev": ev, **fields}
    line = json.dumps(rec, default=str, ensure_ascii=False) + "\n"
    with _lock:
        try:
            with open(_TRACE_PATH, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            # Don't ever raise from a hook — we'd kill the proxy.
            pass


def _peer(conn: Any) -> str | None:
    if conn is None:
        return None
    addr = getattr(conn, "peername", None) or getattr(conn, "address", None)
    if not addr:
        return None
    try:
        return f"{addr[0]}:{addr[1]}"
    except Exception:
        return str(addr)


def _cid(conn: Any) -> str | None:
    if conn is None:
        return None
    return getattr(conn, "id", None) or str(id(conn))


def _record_first(cid: str | None) -> float | None:
    if not cid:
        return None
    now = time.time()
    if cid not in _first_seen:
        _first_seen[cid] = now
        return 0.0
    return now - _first_seen[cid]


# ── Connection lifecycle ───────────────────────────────────────────────
def client_connected(client: Any) -> None:
    cid = _cid(client)
    _record_first(cid)
    _emit("client_connected", cid=cid, peer=_peer(client))


def client_disconnected(client: Any) -> None:
    cid = _cid(client)
    elapsed = None
    if cid in _first_seen:
        elapsed = time.time() - _first_seen.pop(cid)
    _emit("client_disconnected", cid=cid, peer=_peer(client),
          extra={"elapsed_s": elapsed})


def server_connect(data: Any) -> None:
    sc = getattr(data, "server_conn", None) or getattr(data, "conn", None)
    cid = _cid(sc)
    _record_first(cid)
    _emit("server_connect_attempt", cid=cid, peer=_peer(sc),
          sni=getattr(sc, "sni", None))


def server_connected(data: Any) -> None:
    sc = getattr(data, "server_conn", None) or getattr(data, "conn", None)
    cid = _cid(sc)
    dur = _record_first(cid)
    _emit("server_connected", cid=cid, peer=_peer(sc),
          sni=getattr(sc, "sni", None),
          extra={"connect_s": dur})


def server_disconnected(data: Any) -> None:
    sc = getattr(data, "server_conn", None) or getattr(data, "conn", None)
    cid = _cid(sc)
    elapsed = None
    if cid in _first_seen:
        elapsed = time.time() - _first_seen.pop(cid)
    _emit("server_disconnected", cid=cid, peer=_peer(sc),
          err=str(getattr(sc, "error", "") or ""),
          extra={"elapsed_s": elapsed,
                 "tls_version": getattr(sc, "tls_version", None),
                 "cipher": getattr(sc, "cipher", None)})


# ── TLS handshake events ──────────────────────────────────────────────
def tls_clienthello(data: Any) -> None:
    ctx = getattr(data, "context", None)
    client = getattr(ctx, "client", None)
    _emit("tls_clienthello",
          cid=_cid(client),
          peer=_peer(client),
          sni=getattr(getattr(data, "client_hello", None), "sni", None),
          alpn=getattr(getattr(data, "client_hello", None), "alpn_protocols", None),
          extra={"cipher_suites_count":
                 len(getattr(getattr(data, "client_hello", None),
                             "cipher_suites", []) or [])})


def tls_start_client(data: Any) -> None:
    ctx = getattr(data, "context", None)
    client = getattr(ctx, "client", None) if ctx else None
    _emit("tls_start_client",
          cid=_cid(client),
          peer=_peer(client),
          sni=getattr(client, "sni", None),
          alpn=getattr(client, "alpn", None))


def tls_established_client(data: Any) -> None:
    ctx = getattr(data, "context", None)
    client = getattr(ctx, "client", None) if ctx else None
    _emit("tls_established_client",
          cid=_cid(client),
          peer=_peer(client),
          sni=getattr(client, "sni", None),
          alpn=getattr(client, "alpn", None),
          extra={"tls_version": getattr(client, "tls_version", None),
                 "cipher": getattr(client, "cipher", None)})


def tls_failed_client(data: Any) -> None:
    ctx = getattr(data, "context", None)
    client = getattr(ctx, "client", None) if ctx else None
    server = getattr(ctx, "server", None) if ctx else None
    _emit("tls_failed_client",
          cid=_cid(client),
          peer=_peer(client),
          sni=getattr(client, "sni", None),
          err=str(getattr(client, "error", "") or ""),
          extra={"upstream_peer": _peer(server)})


def tls_start_server(data: Any) -> None:
    ctx = getattr(data, "context", None)
    server = getattr(ctx, "server", None) if ctx else None
    _emit("tls_start_server",
          cid=_cid(server),
          peer=_peer(server),
          sni=getattr(server, "sni", None),
          alpn=getattr(server, "alpn", None))


def tls_established_server(data: Any) -> None:
    ctx = getattr(data, "context", None)
    server = getattr(ctx, "server", None) if ctx else None
    _emit("tls_established_server",
          cid=_cid(server),
          peer=_peer(server),
          sni=getattr(server, "sni", None),
          alpn=getattr(server, "alpn", None),
          extra={"tls_version": getattr(server, "tls_version", None),
                 "cipher": getattr(server, "cipher", None)})


def tls_failed_server(data: Any) -> None:
    ctx = getattr(data, "context", None)
    server = getattr(ctx, "server", None) if ctx else None
    _emit("tls_failed_server",
          cid=_cid(server),
          peer=_peer(server),
          sni=getattr(server, "sni", None),
          err=str(getattr(server, "error", "") or ""))


# ── HTTP lifecycle (only the headers — bodies are big and noisy) ──────
def http_connect(flow: Any) -> None:
    req = getattr(flow, "request", None)
    _emit("http_connect",
          cid=getattr(getattr(flow, "client_conn", None), "id", None),
          peer=f"{getattr(req, 'host', '?')}:{getattr(req, 'port', '?')}",
          extra={"http_version": getattr(req, "http_version", None)})


def requestheaders(flow: Any) -> None:
    req = getattr(flow, "request", None)
    if req is None:
        return
    _emit("requestheaders",
          cid=getattr(getattr(flow, "client_conn", None), "id", None),
          peer=f"{req.host}:{req.port}",
          extra={"method": req.method,
                 "scheme": req.scheme,
                 "path": req.path[:200] if req.path else None,
                 "http_version": req.http_version})


def responseheaders(flow: Any) -> None:
    resp = getattr(flow, "response", None)
    req = getattr(flow, "request", None)
    if resp is None or req is None:
        return
    _emit("responseheaders",
          cid=getattr(getattr(flow, "client_conn", None), "id", None),
          peer=f"{req.host}:{req.port}",
          extra={"status": resp.status_code,
                 "ctype": resp.headers.get("content-type"),
                 "clen": resp.headers.get("content-length"),
                 "alt_svc": resp.headers.get("alt-svc")})


def error(flow: Any) -> None:
    req = getattr(flow, "request", None)
    err = getattr(flow, "error", None)
    _emit("flow_error",
          cid=getattr(getattr(flow, "client_conn", None), "id", None),
          peer=f"{getattr(req, 'host', '?')}:{getattr(req, 'port', '?')}" if req else None,
          err=str(getattr(err, "msg", err) or ""),
          extra={"timestamp": getattr(err, "timestamp", None)})
