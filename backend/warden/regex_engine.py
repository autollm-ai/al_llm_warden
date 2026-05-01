"""Tier-1 regex engine. Detects deterministic PII and secret patterns.

Each pattern carries a sensitivity weight. Higher means more dangerous.
The engine returns a list of redacted hits and an aggregate score in [0, 1].
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    weight: float
    category: str


# Compiled once at import.
PATTERNS: list[Pattern] = [
    Pattern(
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        1.0,
        "secret",
    ),
    Pattern(
        "aws_secret_key",
        re.compile(r"(?i)aws(.{0,20})?(secret|access)(.{0,20})?[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
        1.0,
        "secret",
    ),
    Pattern(
        "openai_key",
        re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
        1.0,
        "secret",
    ),
    Pattern(
        "anthropic_key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"),
        1.0,
        "secret",
    ),
    Pattern(
        "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        1.0,
        "secret",
    ),
    Pattern(
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        1.0,
        "secret",
    ),
    Pattern(
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        1.0,
        "secret",
    ),
    Pattern(
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        1.0,
        "secret",
    ),
    Pattern(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        0.85,
        "secret",
    ),
    Pattern(
        "bearer_token",
        re.compile(r"(?i)\b(?:authorization|bearer)\s*[:=]?\s*['\"]?[A-Za-z0-9_\-\.]{20,}['\"]?"),
        0.7,
        "secret",
    ),
    Pattern(
        "credit_card",
        # Anchor on real card prefixes (Visa, MC, Amex, Discover, JCB,
        # Diners) AND require a non-alphanumeric boundary on both sides
        # so a 16-digit run inside base64 / Fernet ciphertext can't match.
        # Luhn is still validated below.
        re.compile(
            r"(?<![A-Za-z0-9])"
            r"(?:"
              r"4\d{3}(?:[ -]?\d{4}){3}"                    # Visa 16
              r"|5[1-5]\d{2}(?:[ -]?\d{4}){3}"              # MasterCard
              r"|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)(?:[ -]?\d{4}){3}"  # MC 2-series
              r"|3[47]\d{2}[ -]?\d{6}[ -]?\d{5}"            # Amex
              r"|6(?:011|5\d{2})(?:[ -]?\d{4}){3}"          # Discover
              r"|35(?:2[89]|[3-8]\d)(?:[ -]?\d{4}){3}"      # JCB
              r"|3(?:0[0-5]|[68]\d)\d(?:[ -]?\d{4})(?:[ -]?\d{4,6})"  # Diners
            r")"
            r"(?![A-Za-z0-9])"
        ),
        0.9,
        "pii",
    ),
    Pattern(
        "ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        0.95,
        "pii",
    ),
    Pattern(
        "email",
        # Local part requires ≥2 chars to keep code idioms like `t@app.get`
        # out of the hit list (`.get`, `.post`, `.delete` are real TLDs).
        re.compile(r"\b[A-Za-z0-9._%+\-]{2,}@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        0.4,
        "pii",
    ),
    Pattern(
        "phone_us",
        re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b"),
        0.5,
        "pii",
    ),
    Pattern(
        "ipv4",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        0.25,
        "pii",
    ),
    Pattern(
        "iban",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
        0.85,
        "pii",
    ),
    Pattern(
        "passport_us",
        re.compile(r"\b[A-Z]\d{8}\b"),
        0.7,
        "pii",
    ),
    Pattern(
        "db_url",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"]+"),
        0.9,
        "secret",
    ),
    Pattern(
        "internal_hostname",
        re.compile(r"\b(?:[a-z0-9\-]+\.)?(?:internal|corp|local|prod|staging|dev)\.[a-z0-9\-\.]+\b"),
        0.4,
        "pii",
    ),
    Pattern(
        "ip_internal",
        re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
        0.55,
        "pii",
    ),
]


@dataclass
class RegexHit:
    name: str
    category: str
    weight: float
    snippet: str           # masked, safe to persist / display
    span: tuple[int, int]
    raw: str = ""          # in-memory only — used for identity comparison;
                           # never serialised to the events table.


def _mask(value: str) -> str:
    if len(value) <= 6:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def scan(text: str, max_hits: int = 50) -> tuple[list[RegexHit], float]:
    """Run all regexes and return hits + aggregate score in [0, 1]."""
    if not text:
        return [], 0.0
    hits: list[RegexHit] = []
    score = 0.0
    for p in PATTERNS:
        for m in p.regex.finditer(text):
            if len(hits) >= max_hits:
                break
            raw = m.group(0)
            # Skip credit-card false positives (very loose pattern)
            if p.name == "credit_card" and not _luhn(re.sub(r"[ -]", "", raw)):
                continue
            hits.append(
                RegexHit(
                    name=p.name,
                    category=p.category,
                    weight=p.weight,
                    snippet=_mask(raw),
                    span=m.span(),
                    raw=raw,
                )
            )
            # Saturating sum: each hit contributes (weight * remaining headroom).
            score = score + p.weight * (1.0 - score) * 0.6
    return hits, min(score, 1.0)


def _luhn(num: str) -> bool:
    if not num.isdigit() or not (13 <= len(num) <= 19):
        return False
    total = 0
    for i, d in enumerate(reversed(num)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0
