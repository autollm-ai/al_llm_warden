"""mitmproxy addon — classifies outbound LLM traffic and logs events.

Run as:
    mitmdump -s /app/proxy/addon.py --listen-host 0.0.0.0 --listen-port 8080

Designed to be transparent: it never blocks traffic. It tags every intercepted
flow with a `X-Warden-Scanned: 1` response header so a validation script can
confirm the proxy is in the path.
"""
from __future__ import annotations

import json
import logging
import os
import sys
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


class Warden:
    def __init__(self) -> None:
        tok_path, model_path = _cls.default_paths()
        self.classifier = _cls.Classifier.from_paths(tok_path, model_path)
        self.store = EventStore()
        log.info(
            "Warden addon loaded — db=%s tier2=%s",
            self.store.path,
            self.classifier.model is not None,
        )

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        provider = lookup_provider(host)
        if provider is None:
            return
        body_bytes = flow.request.raw_content or b""
        if not body_bytes:
            text = ""
        else:
            slice_ = body_bytes[:_MAX_BODY_BYTES]
            try:
                text = slice_.decode("utf-8", errors="replace")
            except Exception:
                text = ""
        text = _flatten_payload(text, flow.request.headers.get("content-type", ""))

        result = self.classifier.classify(text)

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
        )
        try:
            event_id = self.store.insert(event)
        except Exception as e:
            log.warning("Event insert failed: %s", e)
            event_id = -1

        # Tag the request for validation.
        flow.request.headers["X-Warden-Scanned"] = "1"
        flow.request.headers["X-Warden-Label"] = result.label
        flow.metadata["warden_event_id"] = event_id  # metadata lives on the flow

    def response(self, flow: http.HTTPFlow) -> None:
        # Echo confirmation back to the client too — useful for the validator.
        if "X-Warden-Scanned" in flow.request.headers and flow.response is not None:
            flow.response.headers["X-Warden-Scanned"] = "1"
            label = flow.request.headers.get("X-Warden-Label", "clean")
            flow.response.headers["X-Warden-Label"] = label


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


addons = [Warden()]
