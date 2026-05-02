"""Intent classifier — first-stage filter for outbound LLM traffic.

Distinguishes *what kind* of request this is before the regex / DCG /
LSTM pipelines run, so we can demote the noisy buckets:

  • telemetry  — Segment / event_logging / metric flush. UUIDs and
                 model strings here are not "sensitive content".
  • antiabuse  — sentinel / proof-of-work / Fernet-encrypted blobs.
                 Pure noise to the regex engine.
  • handshake  — conversation/init, conversation/prepare. Tiny metadata
                 payloads that carry no user content.
  • auth       — oauth / token / api-key endpoints. Real secrets, keep
                 critical.
  • chat       — actual prompt / completion traffic. Scan aggressively.
  • unknown    — fail-safe; treated as `chat` for severity purposes.

This v1 is rule-based. The interface is `classify(provider, method,
path, content_type, body) -> IntentResult` so a TF-IDF + SVD + LogReg
model can drop in behind it without touching callers once we have
enough captured traffic to train on.

Severity demotion factors (multiplied into the final sensitivity score
before labelling). Scores and hits are still stored truthfully in the
DB; only the *displayed* label and the colour band are demoted.

  chat / auth / unknown : 1.00   (no demotion)
  handshake             : 0.45
  telemetry             : 0.35
  antiabuse             : 0.25

For telemetry / antiabuse / handshake the final label is also clamped
at "low" so the dashboard shows orange (low band) instead of red.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# ── public class set ─────────────────────────────────────────────────
INTENTS = ("chat", "telemetry", "antiabuse", "handshake", "auth", "unknown")

INTENT_FACTOR: dict[str, float] = {
    "chat":      1.00,
    "auth":      1.00,
    "unknown":   1.00,
    "handshake": 0.45,
    "telemetry": 0.35,
    "antiabuse": 0.25,
}

# Intents whose final label is clamped to "low" regardless of score.
DEMOTED = frozenset({"telemetry", "antiabuse", "handshake"})


@dataclass(frozen=True)
class IntentResult:
    intent: str
    confidence: float   # in [0, 1]; rules emit 0.95 / 0.6 / 0.4
    factor: float       # demotion multiplier for sensitivity
    clamp_label: str | None   # max label, or None for no clamp


# ── path-based rules ─────────────────────────────────────────────────
# Order matters: more specific patterns first.

_TELEMETRY_PATHS = re.compile(
    r"""(?ix)
    ^/api/event_logging/    |   # Anthropic Claude-Code internal events
    ^/api/eval/             |   # Anthropic eval SDK (FP from JSONL #2)
    ^/ces/v1/(?:t|m|p|rgstr|telemetry)\b |   # ChatGPT Segment.io intake
    ^/ces/statsc/           |   # ChatGPT histogram flush
    /telemetry/intake\b     |   # Datadog-forwarder intake (ces/v1/telemetry/intake?ddforward=)
    ^/v1/telemetry          |
    /segment\.io/           |
    /analytics/v1/          |
    /metrics/(?:flush|intake|batch)\b |
    /(?:rum|otlp|stats)/    |
    /ingest/(?:event|metric)
    """
)

_ANTIABUSE_PATHS = re.compile(
    r"""(?ix)
    /sentinel/      |
    /turnstile/     |
    /recaptcha/     |
    /chat-requirements/  |
    /pow/           |
    /challenge\b
    """
)

_HANDSHAKE_PATHS = re.compile(
    r"""(?ix)
    /conversation/(?:prepare|init|finalize)\b |
    /conversations/init\b |
    ^/backend-anon/f/conversation/(?:prepare|init|finalize)\b
    """
)

_CHAT_PATHS = re.compile(
    r"""(?ix)
    ^/v1/messages\b              |   # Anthropic
    ^/v1/chat/completions\b      |   # OpenAI
    ^/v1/responses\b             |   # OpenAI Responses API
    ^/v1/complete\b              |
    ^/v1beta/.*generateContent\b |   # Gemini
    ^/api/chat\b                 |   # Mistral, Cohere variants
    ^/backend-(?:api|anon)/(?:f/)?conversation(?:/[^/]+)?$ |
    ^/backend-(?:api|anon)/conversation\b
    """
)

_AUTH_PATHS = re.compile(
    r"""(?ix)
    /oauth(?:2)?/    |
    /token\b         |
    /login\b         |
    /signin\b        |
    /v1/api[_-]?keys\b |
    /auth/(?:login|refresh|exchange)\b
    """
)

# Body shape probes for cases where the path alone is ambiguous.
_FERNET_PREFIX = "gAAAAA"  # cryptography.fernet.Fernet token prefix (b64url of v=0x80)
_BIN_MAGIC = (b"\x1f\x8b", b"\x78\x9c", b"\x78\xda")  # gzip / zlib


def _looks_binary(body_bytes: bytes) -> bool:
    if not body_bytes:
        return False
    if body_bytes[:2] in _BIN_MAGIC:
        return True
    # High proportion of non-utf8 / non-printable bytes → binary
    sample = body_bytes[:512]
    if not sample:
        return False
    # Treat as binary if >30% are outside printable ASCII / common whitespace.
    bad = sum(1 for b in sample if b < 0x09 or (0x0E <= b < 0x20) or b == 0x7F)
    return bad / len(sample) > 0.30


def _looks_chat_payload(body_text: str) -> bool:
    if not body_text:
        return False
    head = body_text[:4096]
    if any(k in head for k in ('"messages"', '"prompt"', '"input"', '"contents"')):
        return True
    # ChatGPT's /backend-anon/f/conversation send is *not* JSON-shaped;
    # we receive a flattened payload containing "user" and "text" tokens
    # alongside the user prompt. Use those as a softer chat signal.
    lower = head.lower()
    return ("\nuser\n" in lower or " user " in lower) and ("\ntext\n" in lower or " text " in lower)


def classify(
    provider: str | None,
    method: str,
    path: str,
    content_type: str,
    body: str | bytes | None,
) -> IntentResult:
    """Rule-based intent classification. Total cost: a handful of regex matches."""
    path = path or ""
    method = (method or "GET").upper()
    body_text: str
    body_bytes: bytes
    if isinstance(body, bytes):
        body_bytes = body
        try:
            body_text = body.decode("utf-8", errors="replace")
        except Exception:
            body_text = ""
    else:
        body_text = body or ""
        body_bytes = body_text.encode("utf-8", errors="replace") if body_text else b""

    # Fast-path: GET / HEAD / OPTIONS rarely carry chat content.
    if method in ("GET", "HEAD", "OPTIONS"):
        # Still let auth/telemetry rules fire — they sometimes use GET.
        pass

    # 1. Anti-abuse BY PATH — most expensive false-positive source.
    if _ANTIABUSE_PATHS.search(path):
        return _result("antiabuse", 0.95)

    # 2. Telemetry BY PATH — must run *before* the antiabuse-by-body
    # check below, otherwise gzip-compressed Segment.io payloads (e.g.
    # /ces/v1/rgstr?gz=1) match the gzip magic bytes and get mis-tagged
    # as antiabuse instead of telemetry.
    if _TELEMETRY_PATHS.search(path):
        return _result("telemetry", 0.95)

    # 3. Anti-abuse BY BODY SHAPE — only reached for paths we don't
    # recognise. Fernet token / gzipped binary blob = not user content.
    if body_text.startswith(_FERNET_PREFIX) or _looks_binary(body_bytes):
        return _result("antiabuse", 0.7)

    # 3. Auth (before handshake/chat — token endpoints can look chat-shaped)
    if _AUTH_PATHS.search(path):
        return _result("auth", 0.9)

    # 4. Handshake — conversation init/prepare with no chat content
    if _HANDSHAKE_PATHS.search(path) and not _looks_chat_payload(body_text):
        return _result("handshake", 0.9)

    # 5. Chat — explicit completion endpoints, OR any path whose body
    # carries chat-shaped content. Body shape wins over a handshake-ish
    # path, since chatgpt.com posts user prompts to `/backend-anon/
    # f/conversation` (no /prepare/init suffix).
    if _CHAT_PATHS.search(path):
        return _result("chat", 0.95)
    if _looks_chat_payload(body_text):
        return _result("chat", 0.7)

    # 6. Trained-model fallback. Only consulted when the rules above all
    # missed — keeps in-distribution traffic on the deterministic path
    # but lets a NB model (trained from the user's own captures via
    # `python -m training.train_intent <jsonl>`) take a shot at novel
    # paths the regex doesn't recognise yet. Returns None until a model
    # is actually trained, in which case we keep the historic 'unknown'
    # behavior — a fresh checkout is fully working with no training step.
    try:
        from warden import intent_model
        guess = intent_model.predict(path, body_text)
    except Exception:
        guess = None
    if guess is not None:
        intent_name, prob = guess
        # NB is badly-calibrated — the threshold is "is the model
        # actually committing" rather than "is it 75% sure". Empirically
        # 0.55 separates 'real signal' from 'no idea'. Anything below
        # falls back to 'unknown' so the UI still shows the user that
        # we don't recognise the path.
        if intent_name in INTENT_FACTOR and prob >= 0.55:
            return _result(intent_name, min(prob, 0.85))

    # 7. Fallback. Treated as `chat` for severity (safer to over-flag than
    # under-flag) but distinguishable in the UI.
    return _result("unknown", 0.4)


def _result(intent: str, confidence: float) -> IntentResult:
    return IntentResult(
        intent=intent,
        confidence=confidence,
        factor=INTENT_FACTOR[intent],
        clamp_label="low" if intent in DEMOTED else None,
    )
