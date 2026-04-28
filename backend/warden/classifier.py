"""Two-tier classifier: regex (deterministic) + LSTM (semantic).

The result is a sensitivity score in [0, 1] plus a human-readable label and
a one-line summary suitable for the dashboard.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import bpe, regex_engine

log = logging.getLogger("warden.classifier")

LABELS = [
    (0.85, "critical"),
    (0.65, "high"),
    (0.40, "medium"),
    (0.15, "low"),
    (0.00, "clean"),
]


def label_for(score: float) -> str:
    for threshold, name in LABELS:
        if score >= threshold:
            return name
    return "clean"


@dataclass
class Classification:
    sensitivity: float
    tier1_score: float
    tier2_score: float
    label: str
    categories: list[str]
    hits: list[dict]
    summary: str

    def to_dict(self) -> dict:
        return {
            "sensitivity": self.sensitivity,
            "tier1_score": self.tier1_score,
            "tier2_score": self.tier2_score,
            "label": self.label,
            "categories": self.categories,
            "hits": self.hits,
            "summary": self.summary,
        }


@dataclass
class Classifier:
    tokenizer: bpe.BPETokenizer | None = None
    model: object | None = None  # lstm.SensitivityLSTM
    device: str = "cpu"
    tier2_weight: float = 0.55  # blend factor; tier-1 still dominates
    _torch_available: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        try:
            import torch  # noqa: F401
            self._torch_available = True
        except Exception:
            self._torch_available = False

    @classmethod
    def from_paths(
        cls,
        tokenizer_path: str | Path | None,
        model_path: str | Path | None,
        device: str = "cpu",
    ) -> "Classifier":
        tok = None
        mdl = None
        if tokenizer_path and Path(tokenizer_path).exists():
            try:
                tok = bpe.BPETokenizer.load(tokenizer_path)
            except Exception as e:
                log.warning("Failed to load BPE tokenizer at %s: %s", tokenizer_path, e)
        if model_path and Path(model_path).exists() and tok is not None:
            try:
                from . import lstm  # imports torch lazily
                mdl = lstm.load(model_path, device=device)
            except Exception as e:
                log.warning("Failed to load LSTM model at %s: %s", model_path, e)
        if mdl is None:
            log.info("Tier-2 LSTM disabled (model or tokenizer missing) — running tier-1 only.")
        return cls(tokenizer=tok, model=mdl, device=device)

    def classify(self, text: str) -> Classification:
        text = text or ""
        hits, tier1 = regex_engine.scan(text)
        tier2 = self._tier2_score(text) if self.model and self.tokenizer else 0.0

        # Blend: take whichever signal is stronger and amplify with the other.
        base = max(tier1, tier2)
        boost = (1.0 - base) * min(tier1, tier2) * self.tier2_weight
        sensitivity = min(1.0, base + boost)

        cats = sorted({h.category for h in hits})
        if tier2 >= 0.5 and not cats:
            cats.append("semantic")

        summary = self._summary(hits, tier1, tier2, sensitivity)
        return Classification(
            sensitivity=round(sensitivity, 4),
            tier1_score=round(tier1, 4),
            tier2_score=round(tier2, 4),
            label=label_for(sensitivity),
            categories=cats,
            hits=[
                {"name": h.name, "category": h.category, "weight": h.weight, "snippet": h.snippet}
                for h in hits
            ],
            summary=summary,
        )

    def _tier2_score(self, text: str) -> float:
        if not self._torch_available or self.tokenizer is None or self.model is None:
            return 0.0
        try:
            import torch
            from . import lstm
            from .char_vocab import chars_to_ids, MAX_CHARS
            from .features import feature_vec
            from .bpe import PAD_ID

            ids, _offsets, surfaces = self.tokenizer.encode_with_offsets(
                text, max_len=lstm.MAX_LEN
            )
            chars = [chars_to_ids(s, MAX_CHARS) for s in surfaces]
            feats = [feature_vec(s) for s in surfaces]
            mask = [int(i != PAD_ID) for i in ids]
            if sum(mask) == 0:
                return 0.0
            ids_t   = torch.tensor([ids],   dtype=torch.long,    device=self.device)
            chars_t = torch.tensor([chars], dtype=torch.long,    device=self.device)
            feats_t = torch.tensor([feats], dtype=torch.float32, device=self.device)
            mask_t  = torch.tensor([mask],  dtype=torch.bool,    device=self.device)
            with torch.no_grad():
                score = self.model.doc_score(ids_t, chars_t, feats_t, mask_t).item()
            return float(score)
        except Exception as e:
            log.warning("LSTM inference failed: %s", e)
            return 0.0

    @staticmethod
    def _summary(hits, tier1: float, tier2: float, sensitivity: float) -> str:
        if not hits and sensitivity < 0.15:
            return "No sensitive content detected."
        parts: list[str] = []
        if hits:
            seen: dict[str, int] = {}
            for h in hits:
                seen[h.name] = seen.get(h.name, 0) + 1
            top = sorted(seen.items(), key=lambda kv: -kv[1])[:3]
            parts.append(
                "Detected " + ", ".join(f"{n.replace('_', ' ')} ×{c}" for n, c in top)
            )
        if tier2 >= 0.5:
            parts.append(f"semantic model flagged sensitive content (p={tier2:.2f})")
        if not parts:
            parts.append(f"low-confidence semantic signal (p={tier2:.2f})")
        return ". ".join(parts) + "."


def default_paths() -> tuple[str, str]:
    base = os.environ.get("WARDEN_MODEL_DIR", "/models")
    return os.path.join(base, "bpe.json"), os.path.join(base, "lstm.pt")
