"""mitmproxy addon — classifies outbound LLM traffic and logs events.

Run as:
    mitmdump -s /app/proxy/addon.py --listen-host 0.0.0.0 --listen-port 8080

Designed to be transparent: it never blocks traffic. It tags every intercepted
flow with a `X-Warden-Scanned: 1` response header so a validation script can
confirm the proxy is in the path.

Test mode (WARDEN_TEST_MODE=1) additionally appends a full request record
per scanned flow to /data/warden-test-mode.jsonl so we can mine endpoints
and payloads later for training the intent and LSTM models. Off by
default; flip it on in docker-compose.yml when you want to capture data.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sys
import threading
from typing import Any

# Allow `python -m` style imports of the warden package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mitmproxy import http  # type: ignore

from warden import classifier as _cls
from warden.database import Event, EventStore, now_iso
from warden.domains import lookup_provider

log = logging.getLogger("warden.proxy")

_MAX_BODY_BYTES = int(os.environ.get("WARDEN_MAX_BODY_BYTES", "131072"))  # 128 KiB
_SAMPLE_CHARS = 400

# ── test-mode capture ────────────────────────────────────────────────
# When WARDEN_TEST_MODE=1, dump the full request body per scanned flow
# to a JSONL file so we can mine traffic for intent / LSTM training.
_TEST_MODE = os.environ.get("WARDEN_TEST_MODE", "0").lower() in ("1", "true", "yes", "on")
_TEST_MODE_PATH = os.environ.get("WARDEN_TEST_MODE_PATH", "/data/warden-test-mode.jsonl")
_TEST_MODE_MAX_BODY = int(os.environ.get("WARDEN_TEST_MODE_MAX_BODY", "262144"))   # 256 KiB
_TEST_MODE_MAX_FILE = int(os.environ.get("WARDEN_TEST_MODE_MAX_FILE", str(200 * 1024 * 1024)))  # 200 MB

# Headers worth keeping for debugging request shape; everything else is
# dropped to avoid persisting auth tokens to disk.
_KEPT_HEADERS = frozenset({
    "content-type", "accept", "user-agent", "x-stainless-os",
    "x-stainless-runtime", "x-stainless-package-version",
    "anthropic-version", "openai-version", "x-request-id",
})


class Warden:
    def __init__(self) -> None:
        tok_path, model_path = _cls.default_paths()
        self.classifier = _cls.Classifier.from_paths(tok_path, model_path)
        self.store = EventStore()
        self._capture = _TestModeCapture(_TEST_MODE_PATH) if _TEST_MODE else None
        log.info(
            "Warden addon loaded — db=%s tier2=%s test_mode=%s",
            self.store.path,
            self.classifier.model is not None,
            bool(self._capture),
        )

    # ─── streaming control ────────────────────────────────────────────────
    # mitmdump runs with --set stream_large_bodies=… so SSE responses (chatgpt
    # token-by-token, claude.ai, gemini) pass through without buffering.
    # That same setting would silently drop the *request* body for the same
    # flows, leaving the classifier with nothing to score. The two hooks
    # below override per-flow:
    #   • requestheaders → force request body to BUFFER (so we can read it).
    #   • responseheaders → force response body to STREAM (so SSE still works).
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        if lookup_provider(flow.request.pretty_host) is not None:
            flow.request.stream = False

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if lookup_provider(flow.request.pretty_host) is None:
            return
        if flow.response is None:
            return
        ctype = (flow.response.headers.get("content-type") or "").lower()
        accept = (flow.request.headers.get("accept") or "").lower()
        is_sse = "text/event-stream" in ctype or "text/event-stream" in accept
        is_chunked = (flow.response.headers.get("transfer-encoding") or "").lower() == "chunked"
        if is_sse or is_chunked:
            flow.response.stream = True

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        provider = lookup_provider(host)
        if provider is None:
            return
        body_bytes = flow.request.raw_content or b""
        content_type = flow.request.headers.get("content-type", "") or ""
        if not body_bytes:
            text = ""
        else:
            slice_ = body_bytes[:_MAX_BODY_BYTES]
            try:
                text = slice_.decode("utf-8", errors="replace")
            except Exception:
                text = ""
        text = _flatten_payload(text, content_type)

        result = self.classifier.classify(
            text,
            provider=provider,
            method=flow.request.method,
            path=flow.request.path,
            content_type=content_type,
        )

        sample = _mask_sample(text)[:_SAMPLE_CHARS]
        event = Event(
            ts=now_iso(),
            host=host,
            provider=provider,
            method=flow.request.method,
            path=flow.request.path,
            sensitivity=result.sensitivity,
            tier1_score=result.tier1_score,
            tier2_score=result.tier2_score,
            label=result.label,
            categories=result.categories,
            hits=result.hits,
            summary=result.summary,
            bytes_out=len(body_bytes),
            sample=sample,
            intent=result.intent,
            intent_conf=result.intent_conf,
            effective_sensitivity=result.effective_sensitivity,
        )
        try:
            event_id = self.store.insert(event)
        except Exception as e:
            log.warning("Event insert failed: %s", e)
            event_id = -1

        if self._capture is not None:
            self._capture.write(flow, body_bytes, result, event_id)

        # Tag the request for validation. Lowercase header names so HTTP/2
        # accepts them without normalisation warnings.
        flow.request.headers["x-warden-scanned"] = "1"
        flow.request.headers["x-warden-label"] = result.label
        flow.request.headers["x-warden-intent"] = result.intent
        flow.metadata["warden_event_id"] = event_id  # metadata lives on the flow

    def response(self, flow: http.HTTPFlow) -> None:
        # Echo confirmation back to the client too — useful for the validator.
        if "x-warden-scanned" in flow.request.headers and flow.response is not None:
            flow.response.headers["x-warden-scanned"] = "1"
            label = flow.request.headers.get("x-warden-label", "clean")
            flow.response.headers["x-warden-label"] = label


def _flatten_payload(text: str, content_type: str) -> str:
    """If the body is JSON (typical for LLM APIs), extract user-visible strings.

    Otherwise return the raw text. Falls back gracefully on parse failure.
    """
    if "json" not in content_type.lower():
        return text
    try:
        obj = json.loads(text)
    except Exception:
        return text
    parts: list[str] = []
    _collect_strings(obj, parts)
    return "\n".join(parts) if parts else text


def _collect_strings(obj: Any, out: list[str]) -> None:
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_strings(v, out)


def _mask_sample(text: str) -> str:
    """Mask obvious secrets in the dashboard preview."""
    from warden.regex_engine import scan
    hits, _ = scan(text, max_hits=20)
    # Apply right-to-left so earlier spans keep their indices.
    spans = sorted(hits, key=lambda h: h.span[0], reverse=True)
    masked = text
    last_start = len(text) + 1
    for h in spans:
        a, b = h.span
        if b > last_start or a < 0 or b > len(masked):
            continue  # overlap with a later (already-replaced) span
        masked = masked[:a] + h.snippet + masked[b:]
        last_start = a
    return masked


class _TestModeCapture:
    """Append-only JSONL writer for full-request capture in test mode.

    One record per scanned flow. Bodies are written verbatim when valid
    UTF-8 (truncated at _TEST_MODE_MAX_BODY) or base64-encoded if binary.
    A coarse size cap rotates the file once it crosses _TEST_MODE_MAX_FILE
    so the volume can't fill up unattended.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            log.info("Test-mode capture enabled → %s", path)
        except Exception as e:
            log.warning("Test-mode capture: cannot create dir for %s: %s", path, e)

    def write(self, flow: http.HTTPFlow, body_bytes: bytes,
              result: Any, event_id: int) -> None:
        try:
            self._maybe_rotate()
            rec = self._build_record(flow, body_bytes, result, event_id)
            line = json.dumps(rec, ensure_ascii=False)
            with self._lock, open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception as e:
            log.warning("Test-mode write failed: %s", e)

    def _maybe_rotate(self) -> None:
        try:
            sz = os.path.getsize(self.path)
        except OSError:
            return
        if sz < _TEST_MODE_MAX_FILE:
            return
        old = self.path + ".1"
        try:
            with self._lock:
                if os.path.exists(old):
                    os.remove(old)
                os.rename(self.path, old)
        except Exception as e:
            log.warning("Test-mode rotate failed: %s", e)

    @staticmethod
    def _build_record(flow: http.HTTPFlow, body_bytes: bytes,
                      result: Any, event_id: int) -> dict:
        headers = {
            k.lower(): v for k, v in flow.request.headers.items()
            if k.lower() in _KEPT_HEADERS
        }
        truncated = len(body_bytes) > _TEST_MODE_MAX_BODY
        sliced = body_bytes[:_TEST_MODE_MAX_BODY]
        try:
            body_text: str | None = sliced.decode("utf-8")
            body_b64: str | None = None
        except UnicodeDecodeError:
            body_text = None
            body_b64 = base64.b64encode(sliced).decode("ascii")
        return {
            "ts": now_iso(),
            "event_id": event_id,
            "host": flow.request.pretty_host,
            "provider": lookup_provider(flow.request.pretty_host),
            "method": flow.request.method,
            "path": flow.request.path,
            "headers": headers,
            "body_bytes": len(body_bytes),
            "body_truncated": truncated,
            "body_text": body_text,
            "body_base64": body_b64,
            "classifier": {
                "intent": result.intent,
                "intent_conf": result.intent_conf,
                "label": result.label,
                "sensitivity": result.sensitivity,
                "effective_sensitivity": result.effective_sensitivity,
                "tier1_score": result.tier1_score,
                "tier2_score": result.tier2_score,
                "categories": result.categories,
                "hits": result.hits,
            },
        }


addons = [Warden()]
