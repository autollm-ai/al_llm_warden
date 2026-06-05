"""
Auto-annotation using Claude API.

Fetches unannotated events from the DB and calls Claude Haiku to assign
ground-truth labels.  Designed to run as a background subprocess.

Usage:
    python -m training.auto_annotate --limit 500
Progress:
    $WARDEN_MODEL_DIR/annotate_status.json
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

_APP = Path(__file__).parent.parent
if str(_APP) not in sys.path:
    sys.path.insert(0, str(_APP))

from warden.database import EventStore, now_iso

_MODEL_DIR = Path(os.environ.get("WARDEN_MODEL_DIR", "/models"))
_STATUS_PATH = _MODEL_DIR / "annotate_status.json"

ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()

_CLASSIFY_PROMPT = """\
You are a security classifier for an LLM proxy system.

Analyze the following text, which is either a prompt sent TO an LLM or a response received FROM one.
Assign it exactly one of these sensitivity labels:

  false_positive — flagged by pattern rules but actually harmless (e.g. fictional names, code examples,
                   educational explanations of security concepts, generic business terms)
  clean          — benign request or response with no sensitive data
  low            — mildly sensitive: internal jargon, generic project names, low-risk context
  medium         — moderate sensitivity: names + contact info, internal hostnames, partial credentials,
                   business data without financial specifics
  high           — high sensitivity: real-looking credentials, PII with name+SSN/DOB/address together,
                   medical records, financial account numbers, production system details
  critical       — maximum sensitivity: live production secrets, complete SSNs with names, full medical
                   records, destructive SQL/shell commands, explicit exfiltration of sensitive data

Text to classify:
---
{text}
---

Reply with ONLY the single label word. No explanation, no punctuation, just the label."""


def _classify(text: str) -> str | None:
    if not ANTHROPIC_KEY:
        return None
    snippet = text[:3000]
    prompt = _CLASSIFY_PROMPT.format(text=snippet)
    payload = json.dumps({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 10,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": ANTHROPIC_KEY,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    _VALID = {"false_positive", "clean", "low", "medium", "high", "critical"}
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read())
            label = body["content"][0]["text"].strip().lower()
            return label if label in _VALID else None
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error", {}).get("message", str(e))
        except Exception:
            msg = str(e)
        print(f"[annotate] HTTP {e.code}: {msg}", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[annotate] {exc}", file=sys.stderr)
        return None


def _write_status(data: dict) -> None:
    try:
        _STATUS_PATH.write_text(json.dumps(data))
    except Exception:
        pass


def run(limit: int = 500) -> None:
    store = EventStore()

    with sqlite3.connect(store.path, timeout=10) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, sample, label FROM events "
            "WHERE ground_truth_label IS NULL AND sample IS NOT NULL AND TRIM(sample) != '' "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()

    total = len(rows)
    done = 0
    ok = 0
    failed = 0
    start_ts = time.time()

    _write_status({"running": True, "done": 0, "total": total, "ok": 0, "started_at": now_iso()})

    for row in rows:
        event_id = row["id"]
        text = (row["sample"] or "").strip()
        if not text:
            done += 1
            continue

        label = _classify(text)
        if label:
            store.annotate_event(event_id, label)
            ok += 1
        else:
            failed += 1

        done += 1
        elapsed = time.time() - start_ts
        rate = done / elapsed if elapsed > 0 else 0
        eta = int((total - done) / rate) if rate > 0 else None
        _write_status({
            "running": True, "done": done, "total": total, "ok": ok, "failed": failed,
            "eta_seconds": eta, "rate": round(rate, 2), "started_at": now_iso(),
        })

        # Respect rate limits: Haiku allows ~50 req/s but we're generous
        time.sleep(0.15)

    _write_status({
        "running": False, "done": done, "total": total, "ok": ok, "failed": failed,
        "finished_at": now_iso(),
    })
    print(f"[auto_annotate] done: {ok}/{total} annotated ({failed} failed)", file=sys.stderr)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Auto-annotate events using Claude API")
    p.add_argument("--limit", type=int, default=500, help="Max events to annotate")
    args = p.parse_args()
    run(limit=args.limit)
