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
import re
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

# ── response monitoring ───────────────────────────────────────────────
# Off by default to keep the original "transparent observation" behavior.
# When on, the addon also classifies the model's *response* body (where
# the actually-dangerous output lives — leaked PII, jailbreak completions,
# harmful generations) and writes it as a second event with
# direction='response'.
_MONITOR_RESPONSES = os.environ.get("WARDEN_MONITOR_RESPONSES", "1").lower() in ("1", "true", "yes", "on")
# Destructive guardrail: when enabled and the response label is in this
# set, replace the response body with a stub before it's delivered to
# the client. This is the actual "guardrail" — observation-only mode
# above just records, this one *blocks*.
_GUARDRAIL_RESPONSES = os.environ.get("WARDEN_GUARDRAIL_RESPONSES", "0").lower() in ("1", "true", "yes", "on")
_GUARDRAIL_LABELS = frozenset(
    s.strip() for s in os.environ.get("WARDEN_GUARDRAIL_LABELS", "critical,high").split(",") if s.strip()
)

# Content-types we'll attempt to score. Anything else (images, audio, octet-
# stream, font payloads, etc.) is skipped — feeding random bytes into the
# UTF-8 decoder + LSTM produces a soup of  replacement chars that the
# semantic head reliably scores as "critical". Source of an early false-pos:
# a gzipped /api/oauth/profile response that the LSTM scored 100%.
_TEXTY_CTYPE_PREFIXES = (
    "application/json",
    "application/x-ndjson",
    "application/x-www-form-urlencoded",
    "application/xml",
    "application/javascript",
    "application/graphql",
    "text/",
)

# RESPONSE-side allowlist is stricter: model APIs return JSON or SSE.
# Anything else (JS bundles, HTML pages, CSS, fonts, images served as
# octet-stream) is browser machinery, not model output. Caught false
# positives:
#   chatgpt.com/cdn/assets/entry.client-XYZ.js  → "application/javascript"
#   downloads.claude.ai/.../latest              → "text/plain" (version str)
# Keeping text/plain off the list because v1 model APIs never use it for
# completions; OpenAI/Anthropic/Gemini all reply application/json or SSE.
_RESPONSE_SCORE_CTYPE_PREFIXES = (
    "application/json",
    "application/x-ndjson",
    "application/graphql",
    "text/event-stream",
)


def _is_scorable_response_ctype(ctype: str) -> bool:
    ct = (ctype or "").split(";", 1)[0].strip().lower()
    if not ct:
        return False
    return ct.startswith(_RESPONSE_SCORE_CTYPE_PREFIXES)
# Above this fraction of UTF-8 replacement chars the body is binary even if
# Content-Type lied — skip rather than score noise.
_REPLACEMENT_CHAR_LIMIT = 0.05

# Path patterns that mean "this isn't model output, don't score the body".
# Two matchers: substrings (anywhere in path) + file extensions (suffix).
# Caught false positives:
#   downloads.claude.ai/claude-code-releases/latest → "2.1.126"
#   chatgpt.com/cdn/assets/entry.client-XYZ.js     → JS bundle
#   /v1/health, /favicon.ico, /static/css/app.css, etc.
_NON_MODEL_PATH_SUBSTRINGS = (
    "release", "version",
    "/health", "/ping", "/livez", "/readyz", "/status",
    "/static/", "/assets/", "/cdn/", "/dist/", "/build/",
    "favicon", "robots.txt", "manifest", "sitemap",
)
_NON_MODEL_PATH_EXTS = (
    ".js", ".mjs", ".css", ".map",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".pdf", ".zip", ".gz", ".br",
    ".html", ".htm",
)


def _is_non_model_path(path: str) -> bool:
    p = (path or "").lower().split("?", 1)[0]
    if any(p.endswith(ext) for ext in _NON_MODEL_PATH_EXTS):
        return True
    return any(hint in p for hint in _NON_MODEL_PATH_SUBSTRINGS)


def _is_texty_ctype(ctype: str) -> bool:
    ct = (ctype or "").split(";", 1)[0].strip().lower()
    if not ct:
        # No declared type → don't risk scoring binary; only score when caller
        # opts in by passing an explicit text-shaped content-type.
        return False
    return ct.startswith(_TEXTY_CTYPE_PREFIXES)


def _decode_for_scoring(body_bytes: bytes, ctype: str) -> str:
    """Return decoded text suitable for the classifier, or '' if the body
    is binary / not worth scoring. Filters used:
      • Empty body → "".
      • Non-text Content-Type → "" (skip image/octet-stream/etc).
      • Decoded text whose replacement-char ratio exceeds the limit →
        "" (binary that lied about its content-type, e.g. compressed
        bytes the caller forgot to decode).
    """
    if not body_bytes:
        return ""
    if not _is_texty_ctype(ctype):
        return ""
    slice_ = body_bytes[:_MAX_BODY_BYTES]
    try:
        text = slice_.decode("utf-8", errors="replace")
    except Exception:
        return ""
    if not text:
        return ""
    bad = text.count("�")
    if bad and bad / max(len(text), 1) > _REPLACEMENT_CHAR_LIMIT:
        return ""
    return text

# ── streaming-response tap ─────────────────────────────────────────────
# Anthropic's /v1/messages, OpenAI's /v1/chat/completions and Gemini all
# stream their responses as SSE (Content-Type: text/event-stream). The
# default mitmproxy behavior when `flow.response.stream = True` is to
# proxy the chunks straight through to the client without ever assembling
# a body — so `flow.response.content` is empty in our `response()` hook
# and we silently skip body classification.
#
# Setting `flow.response.stream` to a *callable* keeps the realtime
# passthrough (each chunk is delivered to the client as it arrives) but
# also lets us peek at every chunk and accumulate them into a side
# buffer. After the stream completes mitmproxy still calls `response()`,
# at which point we assemble the buffer, parse the SSE event stream per
# provider format, extract the assistant's text, and classify.
_MAX_STREAM_CAPTURE = int(os.environ.get("WARDEN_MAX_STREAM_CAPTURE", str(512 * 1024)))  # 512 KiB

# Kill switch for the SSE/chunked tap. Set WARDEN_TAP_STREAMS=0 to fall
# back to the historic stream=True passthrough (response classification
# is silently skipped for streaming responses, exactly as the codebase
# behaved before the tap was introduced). Useful as an instant rollback
# if the tap turns out to interact badly with a specific client (e.g.
# Claude Code's streaming UX going jittery) — flip the env var, restart
# the proxy in ~1s, no rebuild needed. Default ON because that's the
# whole point of monitoring response direction.
_TAP_STREAMS = os.environ.get("WARDEN_TAP_STREAMS", "1").lower() in ("1", "true", "yes", "on")


_BROTLI_WARNED = False


def _decompress_stream_body(body: bytes, content_encoding: str) -> bytes:
    """Decode a stream-tap buffer per Content-Encoding.

    The streaming-response path captures wire bytes pre-decompression
    (mitmproxy's stream callback runs before the content-encoding layer).
    This restores the plaintext for SSE parsing. On decode failure we
    return the original bytes — the parser will still fail soft and the
    flow gets logged as 'scrub-empty', exactly the historic behavior.
    """
    global _BROTLI_WARNED
    enc = (content_encoding or "").strip().lower()
    if not enc or not body:
        return body
    try:
        if "gzip" in enc:
            import gzip
            return gzip.decompress(body)
        if "deflate" in enc:
            import zlib
            try:
                return zlib.decompress(body)
            except zlib.error:
                # Some servers send raw DEFLATE without zlib wrapper.
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if "br" in enc:
            try:
                import brotli  # type: ignore
                return brotli.decompress(body)
            except ImportError:
                if not _BROTLI_WARNED:
                    log.warning(
                        "stream body is brotli-encoded but `brotli` is not installed — "
                        "response classification will see compressed bytes. "
                        "Add `brotli` to backend/requirements.txt to enable."
                    )
                    _BROTLI_WARNED = True
                return body
        if "zstd" in enc:
            try:
                import zstandard  # type: ignore
                return zstandard.ZstdDecompressor().decompress(body)
            except ImportError:
                return body
    except Exception as e:
        log.warning("stream body decompress failed (ce=%r len=%d): %s", enc, len(body), e)
    return body


def _make_stream_tap(flow: "http.HTTPFlow"):
    """Return a callable suitable for `flow.response.stream`.

    The callable is invoked per chunk with `(bytes,)` and must return the
    bytes to forward to the client (we always passthrough unchanged).
    Captured bytes are stashed on `flow.metadata['warden_stream_buf']`
    capped at _MAX_STREAM_CAPTURE — beyond that we keep streaming to the
    client but stop appending to the buffer so memory doesn't blow up
    on a 5-minute Claude-Code conversation.
    """
    buf = bytearray()
    flow.metadata["warden_stream_buf"] = buf
    cap = _MAX_STREAM_CAPTURE

    def tap(chunk: bytes) -> bytes:
        if len(buf) < cap and chunk:
            remaining = cap - len(buf)
            buf.extend(chunk[:remaining])
        return chunk

    return tap


# SSE-line `data:` extractors per provider format. Each takes the raw SSE
# body bytes and returns the assistant's concatenated text content (just
# the text the user would actually see on screen) — never tool-call IDs,
# usage stats, or stop reasons.
def _parse_sse_text(body_bytes: bytes) -> str:
    """Best-effort extractor that handles Anthropic / OpenAI / Gemini SSE
    shapes in one pass. Pulls assistant text AND tool-call payloads — Claude
    Code conversations are dominated by tool_use blocks (Bash/Edit/Read), so
    a parser that only looked at text_delta returned "" for ~every flow and
    the response event never got written.
    """
    try:
        body = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ""
    pieces: list[str] = []
    for line in body.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            obj = json.loads(payload)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        otype = obj.get("type")
        # ── Anthropic /v1/messages ──
        # text_delta:        {"delta":{"type":"text_delta","text":"…"}}
        # input_json_delta:  {"delta":{"type":"input_json_delta","partial_json":"…"}}  ← tool args
        # thinking_delta:    {"delta":{"type":"thinking_delta","thinking":"…"}}
        # content_block_start with tool_use: {"content_block":{"type":"tool_use","name":"Bash","input":{}}}
        if otype == "content_block_delta":
            delta = obj.get("delta") or {}
            if isinstance(delta, dict):
                for key in ("text", "partial_json", "thinking"):
                    v = delta.get(key)
                    if isinstance(v, str) and v:
                        pieces.append(v)
            continue
        if otype == "content_block_start":
            cb = obj.get("content_block") or {}
            if isinstance(cb, dict):
                name = cb.get("name")
                if isinstance(name, str) and name:
                    pieces.append(f"tool:{name}")
                inp = cb.get("input")
                if isinstance(inp, (dict, list)):
                    try:
                        pieces.append(json.dumps(inp, ensure_ascii=False))
                    except Exception:
                        pass
                txt = cb.get("text")
                if isinstance(txt, str) and txt:
                    pieces.append(txt)
            continue
        # ── OpenAI Responses API streaming ──
        # response.output_text.delta:  {"type":"response.output_text.delta","delta":"…"}
        # response.function_call_arguments.delta: {"type":"…","delta":"…"}  ← tool args
        if isinstance(otype, str) and otype.startswith("response."):
            d = obj.get("delta")
            if isinstance(d, str) and d:
                pieces.append(d)
            elif isinstance(d, dict):
                for key in ("text", "value", "arguments"):
                    v = d.get(key)
                    if isinstance(v, str) and v:
                        pieces.append(v)
            continue
        # ── OpenAI /v1/chat/completions ──
        # data: {"choices":[{"delta":{"content":"…","tool_calls":[{"function":{"arguments":"…"}}]}}]}
        if isinstance(obj.get("choices"), list):
            for ch in obj["choices"]:
                if not isinstance(ch, dict):
                    continue
                d = ch.get("delta") or ch.get("message") or {}
                if not isinstance(d, dict):
                    continue
                if isinstance(d.get("content"), str) and d["content"]:
                    pieces.append(d["content"])
                if isinstance(d.get("reasoning"), str) and d["reasoning"]:
                    pieces.append(d["reasoning"])
                tcs = d.get("tool_calls")
                if isinstance(tcs, list):
                    for tc in tcs:
                        if not isinstance(tc, dict):
                            continue
                        fn = tc.get("function") or {}
                        if isinstance(fn, dict):
                            for key in ("name", "arguments"):
                                v = fn.get(key)
                                if isinstance(v, str) and v:
                                    pieces.append(v)
            continue
        # ── Gemini streamGenerateContent ──
        # data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]}}]}
        if isinstance(obj.get("candidates"), list):
            for cand in obj["candidates"]:
                if not isinstance(cand, dict):
                    continue
                content = cand.get("content")
                if not isinstance(content, dict):
                    continue
                for part in content.get("parts", []) or []:
                    if isinstance(part, dict):
                        t = part.get("text")
                        if isinstance(t, str) and t:
                            pieces.append(t)
                        fc = part.get("functionCall")
                        if isinstance(fc, dict):
                            try:
                                pieces.append(json.dumps(fc, ensure_ascii=False))
                            except Exception:
                                pass
            continue
    return "".join(pieces)


def _sse_raw_text_fallback(body_bytes: bytes) -> str:
    """Last-resort SSE flattener used when _parse_sse_text comes up empty.

    Concatenates every `data:` payload (excluding `[DONE]`) verbatim. We
    still want a row in the DB so the operator can see the streaming flow
    happened, even if no provider-specific shape matched. The metadata
    scrubber downstream strips IDs/timestamps before tier-2 sees this.
    """
    try:
        body = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        return ""
    out: list[str] = []
    for line in body.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        out.append(payload)
    return "\n".join(out)


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
            "Warden addon loaded — db=%s tier2=%s test_mode=%s "
            "monitor_responses=%s tap_streams=%s guardrail_responses=%s",
            self.store.path,
            self.classifier.model is not None,
            bool(self._capture),
            _MONITOR_RESPONSES,
            _TAP_STREAMS,
            _GUARDRAIL_RESPONSES,
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
        flow.metadata["warden_is_sse"] = is_sse
        flow.metadata["warden_is_chunked"] = is_chunked
        if (is_sse or is_chunked) and _MONITOR_RESPONSES and _TAP_STREAMS:
            # Tap the stream: chunks pass through to the client in real
            # time AND get accumulated into a side buffer for offline
            # classification once the stream completes. This is what lets
            # us see Claude's reply to a "rm -rf /" prompt — previously
            # we just set stream=True and the body never reached us.
            flow.response.stream = _make_stream_tap(flow)
        elif (is_sse or is_chunked):
            # Either response monitoring is off, or the stream tap kill
            # switch (WARDEN_TAP_STREAMS=0) is engaged. Either way: fall
            # back to the historic passthrough so we never affect the
            # client's streaming UX. Response classification is skipped
            # for this flow; the dashboard will tag it 'x-warden-response-
            # scanned: 0' in the response() hook below.
            flow.response.stream = True
        elif _MONITOR_RESPONSES:
            # Non-streaming response on a known host — force-buffer so we
            # can scan it. mitmproxy respects this even when a global
            # stream_large_bodies is set.
            flow.response.stream = False

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        provider = lookup_provider(host)
        if provider is None:
            return
        # `content` is auto-decompressed per Content-Encoding (gzip/br/
        # deflate); `raw_content` is wire bytes. Use `content` so a gzipped
        # body isn't fed into the decoder as binary noise. `bytes_out` still
        # reports wire bytes for accurate accounting.
        try:
            body_bytes = flow.request.content or b""
        except Exception:
            body_bytes = flow.request.raw_content or b""
        wire_bytes = len(flow.request.raw_content or b"")
        content_type = flow.request.headers.get("content-type", "") or ""
        text = _decode_for_scoring(body_bytes, content_type)
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
            bytes_out=wire_bytes,
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

        # ── Response body classification (the destructive guardrail tier) ──
        # Outbound prompts are one half of the risk; the *response* is the
        # other half — that's where leaked PII regurgitation, jailbroken
        # output, and harmful generations actually appear. Score it the
        # same way and write a separate event with direction='response'.
        if not _MONITOR_RESPONSES:
            return
        if flow.response is None:
            return
        host = flow.request.pretty_host
        provider = lookup_provider(host)
        if provider is None:
            return
        # Streaming responses now go through the tap in responseheaders()
        # — bytes are stashed on flow.metadata['warden_stream_buf']. The
        # buffer-vs-content branching happens inside _streamed_response_body
        # below. The historical "skip if streaming" behavior is preserved
        # only when _MONITOR_RESPONSES is off.
        # Skip auth / handshake / telemetry round-trips — these never carry
        # model output worth scoring, and their bodies are often opaque
        # tokens that score noisily on the LSTM. (Caught a real false
        # positive: gzipped /api/oauth/profile body decoded as binary
        # noise scored 100% critical.)
        req_intent = flow.request.headers.get("x-warden-intent", "")
        if req_intent in ("auth", "handshake", "telemetry", "antiabuse"):
            flow.response.headers["x-warden-response-scanned"] = "0"
            return
        # Skip release / version / static-asset endpoints — these are CDN
        # metadata, not model output. (Caught false positive: GET
        # downloads.claude.ai/claude-code-releases/latest body "2.1.126"
        # scored 100% critical.)
        if _is_non_model_path(flow.request.path):
            flow.response.headers["x-warden-response-scanned"] = "0"
            flow.response.headers["x-warden-response-skip-reason"] = "non-model-path"
            return

        ctype = flow.response.headers.get("content-type", "") or ""
        is_sse = flow.metadata.get("warden_is_sse")
        stream_buf = flow.metadata.get("warden_stream_buf")

        def _write_skipped(reason: str, body_len: int) -> None:
            """Insert a placeholder response row when we decided to skip
            tier-2 classification. Without this, streaming flows whose
            extraction came up empty (or whose body was below the
            min-length floor) left zero trace on the dashboard — the
            operator couldn't tell if the proxy saw the response at all
            or if monitoring was broken. Now there's always a row."""
            try:
                ev = Event(
                    ts=now_iso(),
                    host=host,
                    provider=provider,
                    method=flow.request.method,
                    path=flow.request.path,
                    sensitivity=0.0,
                    tier1_score=0.0,
                    tier2_score=0.0,
                    label="clean",
                    categories=[],
                    hits=[],
                    summary=f"response not scored: {reason}",
                    bytes_out=body_len,
                    sample="",
                    intent=req_intent or "unknown",
                    intent_conf=0.0,
                    effective_sensitivity=0.0,
                    direction="response",
                )
                self.store.insert(ev)
            except Exception as e:
                log.warning("Skipped-response insert failed: %s", e)
            flow.response.headers["x-warden-response-scanned"] = "0"
            flow.response.headers["x-warden-response-skip-reason"] = reason

        # Pick the body source. Streamed responses populate the side
        # buffer set by the tap in responseheaders(); buffered responses
        # use mitmproxy's auto-decompressed content.
        if stream_buf is not None and len(stream_buf) > 0:
            body_bytes = bytes(stream_buf)
            # `flow.response.stream`'s callback delivers wire-level chunks
            # AFTER TLS decryption but BEFORE Content-Encoding decode. The
            # buffered path (`flow.response.content`) auto-decompresses;
            # the streaming path does not. Anthropic returns gzip-encoded
            # SSE on /v1/messages, so without this step the parser sees
            # 1f 8b ... gzip frames, finds zero `data:` lines, and every
            # response gets stamped "scrub-empty" with DCG never running.
            body_bytes = _decompress_stream_body(
                body_bytes, flow.response.headers.get("content-encoding") or ""
            )
            if is_sse:
                text = _parse_sse_text(body_bytes)
                if not text.strip():
                    # Provider-shaped extractor came up empty (e.g. a Claude
                    # Code turn that's pure tool_use deltas the parser
                    # didn't recognise, or a brand-new event shape). Fall
                    # back to a raw flatten of every `data:` line so the
                    # row STILL gets written — operators need to see the
                    # streaming flow even if extraction was lossy.
                    text = _sse_raw_text_fallback(body_bytes)
                    flow.response.headers["x-warden-response-extract"] = "raw-fallback"
                # Skip the strict-ctype gate (we already KNOW this is SSE)
                # and the JSON-flatten step (we just extracted text), but
                # still run the metadata scrubber + min-length floor.
                text = _scrub_metadata(text)
            else:
                # Chunked but not SSE — treat the assembled bytes like a
                # normal response. Often this is a long JSON body that
                # was streamed for size reasons.
                if not _is_scorable_response_ctype(ctype):
                    _write_skipped("non-model-ctype", len(body_bytes))
                    return
                text = _decode_for_scoring(body_bytes, ctype)
                if not text.strip():
                    _write_skipped("decode-empty", len(body_bytes))
                    return
                text = _flatten_payload(text, ctype)
        else:
            # Non-streaming path. Use `content` not `raw_content` —
            # mitmproxy auto-decompresses gzip/br/deflate here.
            try:
                body_bytes = flow.response.content or b""
            except Exception:
                body_bytes = flow.response.raw_content or b""
            if not body_bytes:
                return
            if not _is_scorable_response_ctype(ctype):
                _write_skipped("non-model-ctype", len(body_bytes))
                return
            text = _decode_for_scoring(body_bytes, ctype)
            if not text.strip():
                _write_skipped("decode-empty", len(body_bytes))
                return
            text = _flatten_payload(text, ctype)

        if not text.strip():
            _write_skipped("scrub-empty", len(body_bytes))
            return
        # Note: the historical 32-char min-length floor was here to keep the
        # LSTM from over-firing on tiny payloads. With dcg_only=True on the
        # response path, the LSTM no longer runs, and DCG is precisely the
        # case where short strings matter ("rm -rf" is 6 chars). Floor
        # removed; if it ever needs to come back for a different signal,
        # gate it on something other than length.

        result = self.classifier.classify(
            text,
            provider=provider,
            method=flow.request.method,
            path=flow.request.path,
            content_type=ctype,
            dcg_only=True,
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
            direction="response",
        )
        try:
            self.store.insert(event)
        except Exception as e:
            log.warning("Response event insert failed: %s", e)

        flow.response.headers["x-warden-response-scanned"] = "1"
        flow.response.headers["x-warden-response-label"] = result.label

        # ── Destructive guardrail: redact body when label is critical/high ──
        # This is the only place the addon ever modifies a flow body. Off by
        # default (WARDEN_GUARDRAIL_RESPONSES=0); when on, we replace the
        # body with a small JSON stub explaining what we blocked. The user
        # gets a clear, debuggable error instead of a silent truncation.
        if _GUARDRAIL_RESPONSES and result.label in _GUARDRAIL_LABELS:
            stub = json.dumps({
                "warden_guardrail": True,
                "blocked_label": result.label,
                "categories": result.categories,
                "summary": result.summary,
                "hint": "Set WARDEN_GUARDRAIL_RESPONSES=0 to disable response blocking.",
            }).encode("utf-8")
            flow.response.headers["content-type"] = "application/json"
            flow.response.headers["content-length"] = str(len(stub))
            flow.response.headers["x-warden-blocked"] = "1"
            flow.response.content = stub
            log.info("Guardrail blocked %s %s — label=%s", flow.request.method, flow.request.path, result.label)


# ── Metadata scrubber ────────────────────────────────────────────────
# When users chat with an LLM the request body carries the user's prompt
# *and* a pile of trace/conversation/message IDs, model strings, timezone
# tags, and routing metadata. The LSTM is trained on prose; feeding it
# UUID soup makes the semantic head over-fire near 100%. Real example
# from a "hey" message to chatgpt.com/backend-anon/f/conversation:
#
#   next \n 5b862485-25c4-49ac-8634-4f589f8068b2 \n user \n text \n
#   hey \n 69f5dc1c-a6c4-83ea-8bf9-08738a723287 \n 3064a71e-... \n
#   auto \n success \n Asia/Calcutta \n primary_assistant \n v1 \n ...
#
# The user content is " hey"; everything else is request_id / trace_id /
# message_id / conversation_id / model name / timezone / routing flag.
# These are operationally exempt from sensitivity inspection — they're
# not "what the user typed", they're machine plumbing. Strip them before
# the classifier sees the payload. (Tier-1 regex already runs on the
# *original* text, so secrets in IDs would still be caught upstream.)
_UUID_RE      = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_HEX_ID_RE    = re.compile(r"\b[0-9a-f]{32,}\b", re.I)            # 32+ hex (sha-ish)
_B64_ID_RE    = re.compile(r"\b[A-Za-z0-9_-]{22,}={0,2}\b")       # base64ish ids ≥ 22 chars
_ISO_TS_RE    = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
_TZ_RE        = re.compile(r"\b(?:Africa|America|Antarctica|Asia|Atlantic|Australia|Europe|Indian|Pacific)/[A-Za-z_]+(?:/[A-Za-z_]+)?\b")
# Single short routing/flag tokens that consistently appear as standalone
# values in chat-form payloads. Stripping by *exact line match* only — we
# never want to remove these substrings from the middle of user text.
_NOISE_LINE_TOKENS = frozenset({
    "next", "auto", "success", "true", "false", "null",
    "primary_assistant", "v1", "v2", "v3", "allow", "deny",
    "user", "assistant", "system", "text",
})


def _scrub_metadata(text: str) -> str:
    """Remove machine-plumbing identifiers so the LSTM sees user content.

    Lines that are *only* an ID/timestamp/timezone/routing-flag are dropped
    entirely; mid-line IDs inside prose are blanked. Empty lines collapse.
    """
    if not text:
        return text
    # Drop ID-shaped substrings *inside* lines first (so a line like
    # "request_id=5b86...8068b2" becomes "request_id=").
    cleaned = _UUID_RE.sub("", text)
    cleaned = _HEX_ID_RE.sub("", cleaned)
    cleaned = _ISO_TS_RE.sub("", cleaned)
    cleaned = _TZ_RE.sub("", cleaned)
    out: list[str] = []
    for raw in cleaned.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low in _NOISE_LINE_TOKENS:
            continue
        # Standalone base64ish ID line (be careful: only if the whole line
        # is the ID, not if it's prose containing one).
        if _B64_ID_RE.fullmatch(line):
            continue
        # Lines that are now just punctuation / single chars after stripping.
        if len(line) <= 2 and not any(c.isalpha() for c in line):
            continue
        out.append(raw.rstrip())
    return "\n".join(out)


def _flatten_payload(text: str, content_type: str) -> str:
    """Extract user-visible strings from the body, then scrub IDs/metadata.

    For JSON bodies we recurse and collect string leaves; for other types
    we keep the raw text. Either way the output is run through the
    metadata scrubber so trace/request/message IDs don't reach tier-2.
    """
    raw = text
    if "json" in content_type.lower():
        try:
            obj = json.loads(text)
            parts: list[str] = []
            _collect_strings(obj, parts)
            if parts:
                raw = "\n".join(parts)
        except Exception:
            pass
    return _scrub_metadata(raw)


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
