"""Synthetic training-data generator.

Produces a CSV of (text, label) where label ∈ {0, 1}.
- 0 = benign / non-sensitive
- 1 = contains sensitive content

Sensitive samples mix templates (PII, secrets, credentials, internal hostnames,
proprietary code, financials, medical) with filler text so the LSTM learns
context, not just regex patterns.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import string
from pathlib import Path

# ─── Word banks ─────────────────────────────────────────────────────────────

NEUTRAL_FILLER = (
    "Please summarize the following paragraph in plain English. "
    "I am working on a small project and would like some thoughts on how to "
    "structure this code, particularly around testing strategy. "
    "Could you propose a few alternatives and walk through the tradeoffs in "
    "a way a junior engineer could follow. ").split()

NEUTRAL_TOPICS = [
    "the difference between a hash map and a sorted tree",
    "how to write a clear pull request description",
    "common pitfalls when migrating from Python 2 to Python 3",
    "designing a CLI for a developer audience",
    "the role of a product manager on a small team",
    "writing unit tests for a function that calls an HTTP API",
    "handling time zones correctly in a web app",
    "the history of the Unix philosophy",
    "performance characteristics of a B-tree versus an LSM tree",
    "how rate limiting works in a typical API gateway",
    "JSON serialization edge cases",
    "the role of dependency injection in a Java codebase",
    "best practices for writing meaningful git commit messages",
    "comparing styles of technical writing across teams",
    "an introduction to graph traversal algorithms",
    "how a content delivery network reduces latency",
    "explaining the observer pattern to a beginner",
    "the basics of TCP congestion control",
    "approaches to debounce a search input in a React app",
    "the architectural style of a typical microservice",
]

CODE_SNIPPETS = [
    "def fibonacci(n: int) -> int:\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a",
    "select user_id, count(*) from orders group by user_id order by 2 desc limit 10;",
    "function debounce(fn, ms){ let t; return (...a)=>{ clearTimeout(t); t=setTimeout(()=>fn(...a), ms);} }",
    "git rebase -i origin/main && git push --force-with-lease",
    "for i in range(10):\n    print(i*i)",
]

# ─── Sensitive templates ────────────────────────────────────────────────────

FIRST_NAMES = [
    "Alex", "Priya", "Mei", "Jordan", "Samira", "Diego", "Hannah",
    "Chris", "Tomás", "Aisha", "Wei", "Olivia", "Marcus", "Yuki",
]
LAST_NAMES = [
    "Patel", "Smith", "Nguyen", "Garcia", "Kim", "Johansson", "Okafor",
    "Brown", "Müller", "Tanaka", "Mendoza", "Lee", "Petrov", "Clarke",
]
COMPANIES = [
    "Acme Robotics", "Northwind Logistics", "Helix Biotech", "Aurora Capital",
    "Pinecone Health", "Stellar Foods", "Bluebird Insurance",
]
ROLES = ["VP of Engineering", "Lead Counsel", "CFO", "CISO", "Head of HR"]


def _rand_email() -> str:
    name = random.choice(FIRST_NAMES).lower()
    last = random.choice(LAST_NAMES).lower()
    domain = random.choice(["gmail.com", "acme.co", "northwind.io", "helix.bio", "outlook.com"])
    return f"{name}.{last}{random.randint(1,99)}@{domain}"


def _rand_phone() -> str:
    return f"+1-{random.randint(200,999)}-{random.randint(200,999)}-{random.randint(1000,9999)}"


def _rand_ssn() -> str:
    return f"{random.randint(100,799)}-{random.randint(10,99)}-{random.randint(1000,9999)}"


def _rand_credit_card() -> str:
    # 16 digits passing Luhn.
    digits = [random.randint(0, 9) for _ in range(15)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = d
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    check = (10 - total % 10) % 10
    digits.append(check)
    return "".join(str(d) for d in digits)


def _rand_aws_key() -> str:
    return "AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))


def _rand_aws_secret() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits + "/+", k=40))


def _rand_openai_key() -> str:
    body = "".join(random.choices(string.ascii_letters + string.digits, k=40))
    return f"sk-{body}"


def _rand_gh_token() -> str:
    return "ghp_" + "".join(random.choices(string.ascii_letters + string.digits, k=36))


def _rand_jwt() -> str:
    def part(n: int) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits + "_-", k=n))
    return f"eyJ{part(20)}.{part(40)}.{part(40)}"


def _rand_db_url() -> str:
    return (
        f"postgresql://admin:{_rand_password()}@db-prod-{random.randint(1,9)}."
        f"internal.acme.co:5432/customers"
    )


def _rand_password() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=14))


def _rand_internal_host() -> str:
    return random.choice([
        f"vault-{random.randint(1,9)}.prod.acme.co",
        f"k8s-master-{random.randint(0,5)}.internal.northwind.io",
        f"redis-{random.randint(1,9)}.staging.helix.bio",
    ])


# ─── Sentence builders ──────────────────────────────────────────────────────

def _sensitive_sentence() -> str:
    kind = random.choices(
        ["pii", "secret", "financial", "medical", "credentials", "internal"],
        weights=[3, 4, 2, 2, 3, 2],
    )[0]
    if kind == "pii":
        return random.choice([
            f"Customer {random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)} "
            f"({_rand_email()}, phone {_rand_phone()}, SSN {_rand_ssn()}) is asking for a refund.",
            f"Please update the account for {_rand_email()} — their new card is {_rand_credit_card()}, "
            f"expiring {random.randint(1,12):02d}/{random.randint(26,32)}.",
            f"Patient {random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)} born "
            f"{random.randint(1,12):02d}/{random.randint(1,28):02d}/19{random.randint(40,99)}, "
            f"address 123 Maple Street, contact {_rand_phone()}.",
        ])
    if kind == "secret":
        return random.choice([
            f"Here is the AWS key: {_rand_aws_key()} and secret {_rand_aws_secret()} "
            f"for the production cluster.",
            f"Please debug this — OPENAI_API_KEY={_rand_openai_key()} is failing 401s.",
            f"GitHub token {_rand_gh_token()} is what CI uses to push tags.",
            f"Auth header from staging: Authorization: Bearer {_rand_jwt()}",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z8Q...\n-----END RSA PRIVATE KEY-----",
        ])
    if kind == "financial":
        return random.choice([
            f"Q3 revenue forecast for {random.choice(COMPANIES)} is "
            f"${random.randint(20,500)}M with margin {random.randint(15,45)}% "
            f"(internal — not yet disclosed).",
            f"Wire ${random.randint(50,950)},000 from account {random.randint(10000000,99999999)} "
            f"to IBAN GB{random.randint(10,99)}BARC{random.randint(10000000,99999999)}.",
        ])
    if kind == "medical":
        return random.choice([
            f"Diagnosis: type 2 diabetes, A1C {round(random.uniform(6.5, 11.5),1)}; "
            f"prescribed metformin {random.choice([500,850,1000])}mg twice daily.",
            f"MRI showed a {random.randint(2,9)}mm lesion in the left frontal lobe; "
            f"recommend follow-up in {random.randint(2,12)} weeks.",
        ])
    if kind == "credentials":
        return random.choice([
            f"Login for the admin panel: user=root, password={_rand_password()}.",
            f"DB connection string: {_rand_db_url()}",
            f"VPN cert for {random.choice(FIRST_NAMES)} expires next week, password is {_rand_password()}.",
        ])
    return random.choice([
        f"Please ssh into {_rand_internal_host()} and tail the auth log.",
        f"Internal endpoint http://{_rand_internal_host()}/admin/users is throwing 503s.",
        f"This service runs on 10.0.{random.randint(1,254)}.{random.randint(1,254)} behind the WAF.",
    ])


def _benign_sentence() -> str:
    if random.random() < 0.10:
        return random.choice(CODE_SNIPPETS)
    topic = random.choice(NEUTRAL_TOPICS)
    starter = random.choice([
        "Can you write a paragraph about",
        "I'm trying to understand",
        "What's a good way to explain",
        "Could you give me three bullet points on",
        "Please draft an email summarizing",
        "Help me think through",
    ])
    filler = " ".join(random.choices(NEUTRAL_FILLER, k=random.randint(20, 60)))
    return f"{starter} {topic}. {filler}"


def _clean(s: str) -> str:
    """Collapse all whitespace (incl. newlines from multi-line templates like
    PEM blocks) into single spaces. Keeps char offsets stable across the
    assembled text and the word-truncated form."""
    return " ".join(s.split())


def _make_sample(label: int) -> tuple[str, list[tuple[int, int]]]:
    """Return (text, list of (start, end) char spans that came from a
    `_sensitive_sentence` template).  Span list is empty for label==0.

    Truncates to `target_words`, but **never below the last sensitive span**
    so label==1 samples always retain their positive evidence.
    """
    target_words = random.randint(120, 240)
    parts: list[tuple[str, bool]] = []          # (text, is_sensitive)
    if label == 1:
        n_sens = random.choices([1, 2, 3], weights=[5, 3, 1])[0]
        for _ in range(n_sens):
            parts.append((_clean(_sensitive_sentence()), True))
        while sum(len(p[0].split()) for p in parts) < target_words:
            parts.append((_clean(_benign_sentence()), False))
        random.shuffle(parts)
    else:
        while sum(len(p[0].split()) for p in parts) < target_words:
            parts.append((_clean(_benign_sentence()), False))

    out: list[str] = []
    spans: list[tuple[int, int]] = []
    pos = 0
    for i, (piece_text, is_sens) in enumerate(parts):
        if i > 0:
            out.append(" ")
            pos += 1
        start = pos
        out.append(piece_text)
        pos += len(piece_text)
        if is_sens:
            spans.append((start, pos))
    text = "".join(out)

    # Word-level truncation that NEVER drops a sensitive span.
    words = text.split()
    cum_end: list[int] = []           # cum_end[i] = char pos right after word i
    p = 0
    for w in words:
        p += len(w)
        cum_end.append(p)
        p += 1                        # the single space between words
    max_span_end = max((e for _, e in spans), default=0)
    min_words = 0
    for idx, end_pos in enumerate(cum_end):
        if end_pos >= max_span_end:
            min_words = idx + 1
            break
    effective = max(target_words, min_words)
    if effective < len(words):
        text = " ".join(words[:effective])
        cut = len(text)
        spans = [(s, min(e, cut)) for s, e in spans if s < cut]
    return text, spans


def generate(n_samples: int, out_path: Path, seed: int = 7) -> None:
    random.seed(seed)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label", "spans"])
        for _ in range(n_samples):
            label = 1 if random.random() < 0.5 else 0
            text, spans = _make_sample(label)
            writer.writerow([text, label, json.dumps(spans)])
    print(f"Wrote {n_samples} samples to {out_path}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=8000)
    p.add_argument("--out", type=Path, default=Path("/models/training_data.csv"))
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args()
    generate(args.n, args.out, seed=args.seed)


if __name__ == "__main__":
    main()
