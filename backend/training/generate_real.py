"""
Real LLM event generator — makes live OpenAI API calls, scores each
request/response through the warden classifier, and stores them as events.

Claude events are generated separately on the host via:
    python scripts/generate_real_traffic.py --claude-only --count N
Those calls route through the warden proxy automatically.

Usage:
    python -m training.generate_real --openai 100
Progress:
    $WARDEN_MODEL_DIR/real_generate_status.json
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

_APP = Path(__file__).parent.parent
if str(_APP) not in sys.path:
    sys.path.insert(0, str(_APP))

from warden import classifier as _cls
from warden.database import Event, EventStore, now_iso

_MODEL_DIR = Path(os.environ.get("WARDEN_MODEL_DIR", "/models"))
_STATUS_PATH = _MODEL_DIR / "real_generate_status.json"

OPENAI_KEY = os.environ.get("OPENAI_API_KEY", "").strip()

# ── Prompt bank ───────────────────────────────────────────────────────────────

BENIGN_PROMPTS = [
    "Explain the fan-out problem in social networks and how it's typically solved.",
    "What are the trade-offs between SQL and NoSQL databases?",
    "Summarize the key ideas in 'The Pragmatic Programmer' by Hunt and Thomas.",
    "Write a Python function to find all prime numbers up to N using the Sieve of Eratosthenes.",
    "How does gradient descent work in machine learning? Include a simple example.",
    "Explain Docker networking modes (bridge, host, overlay) and when to use each.",
    "What is the difference between TCP and UDP? When would you choose UDP?",
    "Write a React hook that debounces a value with a configurable delay.",
    "How do you implement a LRU cache in Python without using OrderedDict?",
    "Explain ACID properties in databases with concrete examples.",
    "What is the CAP theorem? Give real-world examples of CP, AP, and CA systems.",
    "How does TLS 1.3 handshake work step by step?",
    "Write a function in Go that reverses a singly linked list.",
    "What are the main architectural differences between REST and GraphQL?",
    "Explain how Kubernetes handles pod scheduling and resource requests vs limits.",
    "Write a SQL query to find the top 5 customers by total purchase amount, including ties.",
    "How does the Python GIL affect multi-threaded programs vs multiprocessing?",
    "What is eventual consistency and how does it differ from strong consistency in distributed systems?",
    "Explain the strategy pattern with a Python example using a payment processor.",
    "How do you detect a cycle in a directed graph? Describe the algorithm.",
    "Write a bash script to monitor disk usage and send an alert when above 80%.",
    "What is the difference between symmetric and asymmetric encryption? When to use each?",
    "Explain how React's virtual DOM diffing algorithm (reconciliation) works.",
    "What are Bloom filters and when are they useful? What are the false positive trade-offs?",
    "How does Apache Kafka guarantee message ordering within a partition?",
    "Explain the difference between optimistic and pessimistic locking in databases.",
    "What is a Merkle tree and where is it used? Explain with a blockchain example.",
    "How do you implement exponential backoff with jitter for API retries?",
    "Write a TypeScript generic function that flattens a nested array to any depth.",
    "Explain how Redis handles persistence with RDB snapshots vs AOF logging.",
    "What are the four pillars of object-oriented programming? Give code examples for each.",
    "How does the BGP routing protocol work at a high level?",
    "Explain the differences between threads, processes, and coroutines in Python.",
    "What is consistent hashing and why is it used in distributed caches?",
    "How does garbage collection work in Go? Explain the tricolor mark-and-sweep algorithm.",
    "Write a simple rate limiter using the token bucket algorithm in Python.",
    "What is the difference between a mutex and a semaphore?",
    "Explain the concept of idempotency in REST APIs. Why does it matter?",
    "How do you design a URL shortener service? Walk through the system design.",
    "What are the trade-offs between microservices and monolithic architectures?",
]

SENSITIVE_PROMPTS = [
    # PII
    "I need to process this employee data: John Smith, SSN 123-45-6789, DOB 1985-03-12, salary $95,000. How should I store this securely?",
    "Help me write a letter to Sarah Johnson at 742 Evergreen Terrace, Springfield, IL 62702. Her account number is ACC-847291 and her email is sarah.j@corp.com.",
    "Can you help me organize this patient data? Name: Maria Garcia, DOB: 1979-11-03, Diagnosis: Type 2 Diabetes, Medications: Metformin 500mg twice daily, Insurance: Blue Cross #BCX-449821-3.",
    # Credentials
    "My API key stopped working: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901. Can you help me debug the authentication issue?",
    "I'm getting auth errors with this config:\nDB_HOST=prod-db.internal.corp.com\nDB_USER=admin\nDB_PASSWORD=P@ssw0rd!2024\nDB_NAME=customers_prod\nHow do I fix connection pooling?",
    "Our GitHub Actions secret DEPLOY_KEY=ghp_xAbC1234567890defGHI is being rejected. What could cause this?",
    "AWS credentials for our prod account:\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nRegion: us-east-1. Please review our IAM policy.",
    # Financial
    "Please review this invoice: Client: TechCorp Inc, Invoice #INV-2024-0892, Amount: $847,500, Bank: Chase, Routing: 021000021, Account: 4829103847291.",
    "Help me format this expense report. Credit card: 4532 8819 2947 1028 (expires 09/26), statement balance $12,847.93 as of March 2024.",
    # Medical
    "Draft a patient summary for Dr. Chen: Patient DOB 1962-07-14, MRN: 8847291-A, HIV positive diagnosed 2019, current CD4 count 450 cells/mm3, on Biktarvy (bictegravir/emtricitabine/TAF).",
    "Organize this clinical note: Patient James Wilson, 58 yr male, DOB 04/22/1966, SSN 987-65-4321, admitted for acute MI. Allergies: penicillin. Emergency contact: wife Mary Wilson 555-0142.",
    # Infrastructure secrets
    "Our production server is at 192.168.1.50 with root password Tr0ub4dor&3. SSH port 2222. How do I safely rotate credentials on a live system?",
    "Stripe live secret key sk_live_51abc123def456ghi789jkl012mno345 is showing as unauthorized. Help me debug the payment webhook.",
    # PII in code
    "I have this code with hardcoded user data:\nusers = [{'name': 'Alice Brown', 'email': 'alice.brown@acme.com', 'ssn': '234-56-7890', 'salary': 87000}]\nHow do I safely refactor this to use a database?",
    # Business confidential
    "Review this acquisition term sheet (strictly confidential): Target: DataFlow AI Inc, Valuation: $45M pre-money, Deal: 60% cash $27M + 40% equity, Closing: Q2 2024, Exclusivity: 30 days.",
    # Destructive commands
    "What happens if I run this on production?\nDROP TABLE users;\nDELETE FROM backups WHERE created_at < '2024-01-01';\nTRUNCATE TABLE audit_logs;",
    # Mixed sensitive in logs
    "Debugging prod issue. Error log:\n[ERROR] 2024-03-15 auth failed for user 'dbadmin' password 'myS3cur3P@ss'\nServer: 10.0.1.45:5432 DB: production_db\nHelp me fix without exposing creds.",
    # Slack token
    "My Slack bot token xoxb-abc-123-def456ghi789jkl012mno345pqr is posting to wrong channels. How do I scope it correctly?",
    # Personal medical
    "I've been diagnosed with bipolar II disorder. My psychiatrist prescribed lithium 300mg and quetiapine 25mg. What are the long-term side effects I should know about?",
    # Legal confidential
    "This is from our legal team (attorney-client privileged): The Doe v. AcmeCorp settlement offer is $2.3M, plaintiff's bottom line is $1.8M. How should we counteroffer?",
]


def _write_status(data: dict) -> None:
    try:
        _STATUS_PATH.write_text(json.dumps(data))
    except Exception:
        pass


def _call_openai(prompt: str) -> str | None:
    if not OPENAI_KEY:
        return None
    payload = json.dumps({
        "model": "gpt-4o-mini",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read())
            return body["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error", {}).get("message", str(e))
        except Exception:
            msg = str(e)
        print(f"[openai] HTTP {e.code}: {msg}", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[openai] {exc}", file=sys.stderr)
        return None


def _insert(store: EventStore, clf: _cls.Classifier, text: str,
            provider: str, host: str, path: str, direction: str) -> None:
    result = clf.classify(text)
    store.insert(Event(
        ts=now_iso(),
        host=host,
        provider=provider,
        method="POST",
        path=path,
        sensitivity=result.sensitivity,
        tier1_score=result.tier1_score,
        tier2_score=result.tier2_score,
        label=result.label,
        categories=result.categories,
        hits=result.hits,
        summary=result.summary,
        bytes_out=len(text.encode()),
        sample=text[:2000],
        intent=result.intent,
        intent_conf=result.intent_conf,
        effective_sensitivity=result.effective_sensitivity,
        direction=direction,
    ))


def run(openai_count: int = 0) -> None:
    import random

    store = EventStore()
    tok_path, model_path = _cls.default_paths()
    clf = _cls.Classifier.from_paths(tok_path, model_path)

    rng = random.Random()
    all_prompts = BENIGN_PROMPTS + SENSITIVE_PROMPTS
    total = openai_count
    done = 0
    ok = 0
    start_ts = time.time()

    _write_status({"running": True, "done": 0, "total": total, "ok": 0, "started_at": now_iso()})

    def _status_update() -> None:
        elapsed = time.time() - start_ts
        rate = done / elapsed if elapsed > 0 else 0
        eta = int((total - done) / rate) if rate > 0 else None
        _write_status({
            "running": True, "done": done, "total": total, "ok": ok,
            "eta_seconds": eta, "rate": round(rate, 2), "started_at": now_iso(),
        })

    for _ in range(openai_count):
        prompt = rng.choice(all_prompts)
        try:
            _insert(store, clf, prompt, "OpenAI", "api.openai.com", "/v1/chat/completions", "request")
        except Exception:
            pass
        try:
            resp = _call_openai(prompt)
            if resp:
                _insert(store, clf, resp, "OpenAI", "api.openai.com", "/v1/chat/completions", "response")
                ok += 1
        except Exception:
            pass
        done += 1
        _status_update()

    _write_status({
        "running": False, "done": done, "total": total, "ok": ok,
        "finished_at": now_iso(),
    })
    print(f"[generate_real] done: {done} calls, {ok} API responses recorded", file=sys.stderr)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Generate real OpenAI events via live API calls")
    p.add_argument("--openai", type=int, default=0, help="Number of OpenAI API calls")
    args = p.parse_args()
    if args.openai == 0:
        p.error("specify --openai N")
    run(openai_count=args.openai)
