"""Shadow-AI domain registry.

The static ``SHADOW_AI_DOMAINS`` dict below is the *seed list* — values that
the dashboard pre-populates on first boot. Live state lives in the SQLite
``domains`` table (see ``DomainStore``), so users can add/remove/disable
domains from the UI without redeploying.

``lookup_provider(host)`` is the single entry point used by the proxy
addon. It returns the live label for any enabled host, or None for
anything else (which causes the addon to ignore the flow entirely).

The lookup is backed by a tiny TTL cache (default 5 s) so we don't hit
SQLite on every request, while still picking up UI edits within a few
seconds without a restart.
"""
from __future__ import annotations

import os
import threading
import time

SHADOW_AI_DOMAINS: dict[str, str] = {
    "api.openai.com": "OpenAI",
    "chat.openai.com": "ChatGPT",
    "chatgpt.com": "ChatGPT",
    "api.anthropic.com": "Anthropic",
    "claude.ai": "Claude",
    "console.anthropic.com": "Anthropic Console",
    "generativelanguage.googleapis.com": "Google Gemini",
    "gemini.google.com": "Google Gemini",
    "api.cohere.ai": "Cohere",
    "api.mistral.ai": "Mistral",
    "api.perplexity.ai": "Perplexity",
    "api.together.xyz": "Together AI",
    "api.groq.com": "Groq",
    "api.deepseek.com": "DeepSeek",
    "api.x.ai": "xAI Grok",
    "openrouter.ai": "OpenRouter",
    "api.fireworks.ai": "Fireworks AI",
    "huggingface.co": "Hugging Face",
    "api-inference.huggingface.co": "Hugging Face Inference",
    "copilot.microsoft.com": "Microsoft Copilot",
    "api.replicate.com": "Replicate",
}


_CACHE_TTL = float(os.environ.get("WARDEN_DOMAIN_CACHE_TTL", "5"))
_cache_lock = threading.Lock()
_cache: dict[str, str] = {}
_cache_expires: float = 0.0
_store = None  # set lazily to avoid circular import at module load


def _get_store():
    global _store
    if _store is None:
        # Local import to break the circular dependency chain
        # (warden.database imports nothing from this module, but the proxy
        # addon imports both — keeping this lazy is just hygienic).
        from warden.database import DomainStore
        s = DomainStore()
        s.ensure_seeded(SHADOW_AI_DOMAINS)
        _store = s
    return _store


def _refresh_cache_if_stale() -> dict[str, str]:
    global _cache, _cache_expires
    now = time.monotonic()
    with _cache_lock:
        if now < _cache_expires and _cache:
            return _cache
        try:
            fresh = _get_store().enabled_map()
            _cache = fresh
            _cache_expires = now + _CACHE_TTL
        except Exception:
            # If the DB is unavailable, fall back to seed list so we
            # don't go completely blind. Re-checked again next tick.
            if not _cache:
                _cache = dict(SHADOW_AI_DOMAINS)
                _cache_expires = now + 1.0
        return _cache


def invalidate_cache() -> None:
    """Force the next lookup to re-read from DB. Called by the API after
    add/remove/toggle so UI edits feel instant."""
    global _cache_expires
    with _cache_lock:
        _cache_expires = 0.0


def lookup_provider(host: str) -> str | None:
    """Return provider label if host is a known shadow-AI endpoint."""
    if not host:
        return None
    host = host.lower().split(":", 1)[0]
    table = _refresh_cache_if_stale()
    if host in table:
        return table[host]
    # Suffix match for subdomains (e.g. eu.api.openai.com)
    for known, label in table.items():
        if host.endswith("." + known) or host.endswith(known):
            return label
    return None


def is_shadow_ai(host: str) -> bool:
    return lookup_provider(host) is not None
