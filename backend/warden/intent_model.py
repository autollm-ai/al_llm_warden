"""Numpy-only inference for the trained intent fallback model.

Loaded lazily on first use. If the model files aren't present (no
training has been run yet), ``predict`` returns ``None`` and the rule
classifier in ``warden.intent`` falls back to its existing ``unknown``
behavior. This keeps a fresh checkout fully working without requiring
a training step.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Optional

import numpy as np

_MODEL_DIR = Path(os.environ.get("WARDEN_MODELS_DIR", "/models"))
_MODEL_PATH = _MODEL_DIR / "intent_nb.npz"
_META_PATH = _MODEL_DIR / "intent_nb_meta.json"

_lock = threading.Lock()
_state: dict | None = None  # {'log_prior', 'log_lik', 'intents', 'num_buckets'} or None
_load_attempted = False


def _hash(token: str, salt: str = "") -> int:
    """Must match training/train_intent.py._hash exactly."""
    h = 1469598103934665603
    for ch in salt + token:
        h ^= ord(ch)
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    # The bucket count is read from the model meta at load time so we can't
    # cap here without it; caller takes the modulo with num_buckets.
    return h


def _featurize(path: str, body: str, num_buckets: int) -> np.ndarray:
    v = np.zeros(num_buckets, dtype=np.int32)
    p = (path or "").lower()
    for i in range(max(len(p) - 2, 0)):
        v[_hash(p[i:i+3], "p:") % num_buckets] += 1
    for tok in (body or "").lower().split():
        if 2 <= len(tok) <= 40:
            v[_hash(tok, "b:") % num_buckets] += 1
    return v


def _load_if_needed() -> dict | None:
    global _state, _load_attempted
    with _lock:
        if _state is not None:
            return _state
        if _load_attempted:
            return None
        _load_attempted = True
        try:
            if not (_MODEL_PATH.exists() and _META_PATH.exists()):
                return None
            with np.load(_MODEL_PATH) as z:
                log_prior = z["log_prior"]
                log_lik = z["log_lik"]
            meta = json.loads(_META_PATH.read_text())
            _state = {
                "log_prior": log_prior,
                "log_lik": log_lik,
                "intents": meta["intents"],
                "num_buckets": int(meta["num_buckets"]),
            }
            return _state
        except Exception:
            # Corrupt or shape-mismatched model — silently disable rather
            # than break the proxy. Re-train to recover.
            _state = None
            return None


def predict(path: str, body: str) -> Optional[tuple[str, float]]:
    """Return (intent, probability) or None if the model is unavailable.

    Caller is the rule classifier in ``warden.intent``; it should only
    consult this fallback when its own rules return ``unknown`` (or low
    confidence). The probability comes from softmax-ing the NB scores —
    NB is famously badly-calibrated, so don't trust the magnitude beyond
    "is it above threshold X" decisions.
    """
    s = _load_if_needed()
    if s is None:
        return None
    feats = _featurize(path, body, s["num_buckets"])
    scores = s["log_prior"] + s["log_lik"] @ feats
    # Softmax for a relative confidence; subtract max for numerical stability.
    exps = np.exp(scores - scores.max())
    probs = exps / exps.sum()
    idx = int(probs.argmax())
    return s["intents"][idx], float(probs[idx])
