"""Train the intent fallback model from a test-mode JSONL capture.

The intent classifier in ``warden.intent`` is rule-based regex first; this
script trains a tiny hashing-trick multinomial NB model that catches the
*novel* paths the rules don't recognise yet (today's regex returns
``unknown`` ~32% of the time on the user's own traffic — that's where the
model earns its keep).

Pipeline
--------
1. Read every record in the JSONL and re-derive the **correct** intent
   label by running each path/body through the *current* rule classifier.
   This way the captured-time intent (which had the ordering bug + the
   missing ``/api/eval/`` rule + the gzip-vs-telemetry confusion) is
   discarded and we use the post-fix rules as the labelling oracle.
   Records the rules now resolve confidently (``confidence ≥ 0.7``) become
   training rows; truly ``unknown`` records are dropped — we don't want to
   teach the model to predict "unknown".
2. Hash-trick featurise: path char-trigrams + body word tokens → a fixed
   ``NUM_BUCKETS``-dim sparse count vector. No vocab to persist beyond a
   single int.
3. Multinomial NB with Laplace smoothing — closed-form fit, ~milliseconds
   on 1k records, robust under class imbalance, and the inference is one
   sparse matmul + argmax (numpy only — no torch / sklearn at runtime).
4. Save weights to ``/models/intent_nb.npz`` and a meta sidecar.

Usage
-----
    python -m training.train_intent /path/to/warden-test-mode-*.jsonl

Or inside the container:
    docker compose exec warden-proxy \\
        python -m training.train_intent /data/warden-test-mode.jsonl
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from pathlib import Path

import numpy as np

from warden.intent import INTENTS, classify

NUM_BUCKETS = int(os.environ.get("WARDEN_INTENT_BUCKETS", "1024"))
MODEL_DIR = Path(os.environ.get("WARDEN_MODELS_DIR", "/models"))
MODEL_PATH = MODEL_DIR / "intent_nb.npz"
META_PATH = MODEL_DIR / "intent_nb_meta.json"
MIN_CONF_FOR_TRAIN = float(os.environ.get("WARDEN_INTENT_MIN_CONF", "0.7"))


def _hash(token: str, salt: str = "") -> int:
    """Stable cross-process hash → bucket index. Python's built-in hash()
    is salted per-process, so we use a dead-simple polynomial rolling hash
    that's deterministic across runs and processes."""
    h = 1469598103934665603
    for ch in salt + token:
        h ^= ord(ch)
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h % NUM_BUCKETS


def featurize(path: str, body: str) -> np.ndarray:
    """Hash-trick bag of:
      • path char trigrams (with prefix 'p:')
      • body word tokens   (with prefix 'b:'), lowercased, len ≥ 2.
    Returns a dense (NUM_BUCKETS,) int32 count vector — the matrices we
    train on are small enough that dense beats scipy.sparse in wall time.
    """
    v = np.zeros(NUM_BUCKETS, dtype=np.int32)
    p = (path or "").lower()
    for i in range(max(len(p) - 2, 0)):
        v[_hash(p[i:i+3], "p:")] += 1
    for tok in (body or "").lower().split():
        if len(tok) >= 2 and len(tok) <= 40:
            v[_hash(tok, "b:")] += 1
    return v


def load_dataset(jsonl_path: Path) -> tuple[np.ndarray, np.ndarray, dict]:
    """Walk the JSONL, re-label with current rules, return (X, y, stats)."""
    label_idx = {name: i for i, name in enumerate(INTENTS)}
    rows_X: list[np.ndarray] = []
    rows_y: list[int] = []
    stats = collections.Counter()
    skipped = collections.Counter()
    with jsonl_path.open() as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                r = json.loads(ln)
            except json.JSONDecodeError:
                skipped["bad-json"] += 1
                continue
            path = r.get("path", "") or ""
            method = r.get("method", "GET") or "GET"
            ctype = (r.get("headers") or {}).get("content-type", "") or ""
            body = r.get("body_text") or ""
            if not body and r.get("body_base64"):
                # Don't bother decoding b64-only bodies — they're binary
                # blobs (gzipped/encrypted). Path features alone will do.
                body = ""
            ir = classify(provider=r.get("provider"), method=method,
                          path=path, content_type=ctype, body=body)
            if ir.intent == "unknown" or ir.confidence < MIN_CONF_FOR_TRAIN:
                skipped[f"unknown-or-low-conf:{ir.intent}"] += 1
                continue
            rows_X.append(featurize(path, body))
            rows_y.append(label_idx[ir.intent])
            stats[ir.intent] += 1
    if not rows_X:
        raise SystemExit(
            f"No usable training rows in {jsonl_path} — every record was either "
            f"unparseable or labelled 'unknown'. Capture more traffic and retry."
        )
    return (
        np.stack(rows_X),
        np.asarray(rows_y, dtype=np.int64),
        {"per_class": dict(stats), "skipped": dict(skipped),
         "rows": len(rows_X), "buckets": NUM_BUCKETS},
    )


def fit_nb(X: np.ndarray, y: np.ndarray, num_classes: int, alpha: float = 1.0):
    """Closed-form multinomial Naive Bayes with Laplace smoothing.

    Returns (log_prior[C], log_likelihood[C, F]). Predictions are
        scores = log_prior + X @ log_likelihood.T   →   argmax over classes.
    """
    log_prior = np.zeros(num_classes, dtype=np.float64)
    log_lik = np.zeros((num_classes, X.shape[1]), dtype=np.float64)
    for c in range(num_classes):
        mask = (y == c)
        log_prior[c] = np.log(max(mask.sum(), 1) / len(y))
        feature_counts = X[mask].sum(axis=0).astype(np.float64) + alpha
        log_lik[c] = np.log(feature_counts / feature_counts.sum())
    return log_prior, log_lik


def evaluate(X: np.ndarray, y: np.ndarray, log_prior, log_lik) -> dict:
    scores = log_prior[None, :] + X @ log_lik.T
    pred = scores.argmax(axis=1)
    acc = float((pred == y).mean())
    per_class: dict = {}
    for c, name in enumerate(INTENTS):
        mask = (y == c)
        if mask.sum() == 0:
            continue
        per_class[name] = {
            "support": int(mask.sum()),
            "recall": float((pred[mask] == c).mean()),
        }
    return {"accuracy": acc, "per_class": per_class}


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("jsonl", type=Path, help="path to a warden-test-mode-*.jsonl capture")
    p.add_argument("--out-dir", type=Path, default=MODEL_DIR)
    args = p.parse_args(argv)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Reading {args.jsonl}")
    X, y, stats = load_dataset(args.jsonl)
    print(f"  {stats['rows']} usable rows; per-class = {stats['per_class']}")
    print(f"  skipped: {stats['skipped']}")

    log_prior, log_lik = fit_nb(X, y, num_classes=len(INTENTS))
    metrics = evaluate(X, y, log_prior, log_lik)
    print(f"\nTraining accuracy: {metrics['accuracy']:.3f}")
    for name, st in metrics["per_class"].items():
        print(f"  {name:12s}  support={st['support']:5d}  recall={st['recall']:.3f}")

    out_npz = args.out_dir / "intent_nb.npz"
    out_meta = args.out_dir / "intent_nb_meta.json"
    np.savez_compressed(out_npz, log_prior=log_prior, log_lik=log_lik)
    out_meta.write_text(json.dumps({
        "intents": list(INTENTS),
        "num_buckets": NUM_BUCKETS,
        "rows_trained_on": int(stats["rows"]),
        "per_class_support": stats["per_class"],
        "training_accuracy": metrics["accuracy"],
        "per_class_recall": {k: v["recall"] for k, v in metrics["per_class"].items()},
        "source_jsonl": str(args.jsonl),
    }, indent=2))
    print(f"\nSaved {out_npz} and {out_meta}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
