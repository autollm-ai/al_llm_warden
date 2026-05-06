"""Two-tier classifier: regex (deterministic) + LSTM (semantic).

The result is a sensitivity score in [0, 1] plus a human-readable label and
a one-line summary suitable for the dashboard.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import bpe, dcg, intent as intent_mod, regex_engine
from .identity import IdentityMemory, KIND_FOR_HIT

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


_LABEL_RANK = {name: i for i, (_, name) in enumerate(reversed(LABELS))}


def _clamp_label(label: str, ceiling: str | None) -> str:
    if ceiling is None:
        return label
    return label if _LABEL_RANK[label] <= _LABEL_RANK[ceiling] else ceiling


@dataclass
class Classification:
    sensitivity: float          # raw blended score (kept for audit)
    tier1_score: float
    tier2_score: float
    label: str                  # post-intent-clamp label, this is what the UI shows
    categories: list[str]
    hits: list[dict]
    summary: str
    intent: str = "unknown"
    intent_conf: float = 0.0
    effective_sensitivity: float = 0.0   # sensitivity * intent factor

    def to_dict(self) -> dict:
        return {
            "sensitivity": self.sensitivity,
            "tier1_score": self.tier1_score,
            "tier2_score": self.tier2_score,
            "label": self.label,
            "categories": self.categories,
            "hits": self.hits,
            "summary": self.summary,
            "intent": self.intent,
            "intent_conf": self.intent_conf,
            "effective_sensitivity": self.effective_sensitivity,
        }


@dataclass
class Classifier:
    tokenizer: bpe.BPETokenizer | None = None
    model: object | None = None  # lstm.SensitivityLSTM
    device: str = "cpu"
    tier2_weight: float = 0.55  # blend factor; tier-1 still dominates
    identity: IdentityMemory | None = None
    _torch_available: bool = field(init=False, default=False)

    def __post_init__(self) -> None:
        try:
            import torch  # noqa: F401
            self._torch_available = True
        except Exception:
            self._torch_available = False
        if self.identity is None:
            try:
                self.identity = IdentityMemory()
            except Exception as e:
                log.warning("IdentityMemory unavailable, exemption disabled: %s", e)
                self.identity = None

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

    def classify(
        self,
        text: str,
        *,
        provider: str | None = None,
        method: str = "POST",
        path: str = "",
        content_type: str = "",
        dcg_only: bool = False,
        force_critical_on_dcg: bool = False,
    ) -> Classification:
        # dcg_only: skip PII regex + LSTM, run DCG only. Used on the response
        # direction — the model echoing back user PII is operator-uninteresting
        # noise (the user just typed it), and the LSTM over-fires on response
        # bodies. Destructive-command detection is the only response signal
        # worth keeping.
        # force_critical_on_dcg: when DCG fires, pin label to "critical"
        # regardless of severity tier. Destructive commands are categorical,
        # not graduated — a single hit shouldn't land at "low" because the
        # saturating-sum scales it down. Used on response direction so any
        # rm -rf / drop / terraform destroy / etc. surfaced by the model
        # gets immediate operator attention.
        text = text or ""
        if dcg_only:
            re_hits = []
            re_score = 0.0
        else:
            re_hits, _re_score_raw = regex_engine.scan(text)

            # Identity exemption: observe every email/IP, then for any hit
            # whose raw value qualifies as user-owned (≥THRESHOLD recent
            # recurrences), demote to a low-weight 'user_identity' category.
            # Recompute the regex score from the filtered weights so the
            # exempted hits don't drive the band.
            re_hits = self._apply_identity_exemption(re_hits)
            re_score = 0.0
            for h in re_hits:
                re_score = re_score + h.weight * (1.0 - re_score) * 0.6
            re_score = min(re_score, 1.0)

        dc_hits, dc_score = dcg.scan(text)
        hits = re_hits + dc_hits
        # Treat the two tier-1 pipelines as independent saturating signals.
        tier1 = re_score + (1.0 - re_score) * dc_score
        tier2 = 0.0 if dcg_only else (self._tier2_score(text) if self.model and self.tokenizer else 0.0)

        # Blend: take whichever signal is stronger and amplify with the other.
        base = max(tier1, tier2)
        boost = (1.0 - base) * min(tier1, tier2) * self.tier2_weight
        sensitivity = min(1.0, base + boost)

        cats = sorted({h.category for h in hits})
        if tier2 >= 0.5 and not cats:
            cats.append("semantic")

        # Intent demotion: telemetry / antiabuse / handshake bodies look
        # noisy to the regex engine but carry no real user content. We
        # demote the score and clamp the label, but leave the raw scores
        # and hits intact so the audit trail stays truthful.
        ir = intent_mod.classify(provider, method, path, content_type, text)
        effective = min(1.0, sensitivity * ir.factor)
        label = _clamp_label(label_for(effective), ir.clamp_label)

        # Categorical floor for destructive commands. Applied AFTER the
        # intent clamp so a "chat"-class flow can't down-rank a real
        # destructive hit. Lift effective_sensitivity to 1.0 so the
        # dashboard percentage matches the label (a "critical · 36%"
        # badge would just look broken). Raw sensitivity / tier scores
        # are preserved on the dataclass for audit.
        if force_critical_on_dcg and dc_hits:
            label = "critical"
            effective = 1.0

        summary = self._summary(hits, tier1, tier2, sensitivity, ir)
        return Classification(
            sensitivity=round(sensitivity, 4),
            tier1_score=round(tier1, 4),
            tier2_score=round(tier2, 4),
            label=label,
            categories=cats,
            hits=[
                {"name": h.name, "category": h.category, "weight": h.weight, "snippet": h.snippet}
                for h in hits
            ],
            summary=summary,
            intent=ir.intent,
            intent_conf=round(ir.confidence, 3),
            effective_sensitivity=round(effective, 4),
        )

    def _apply_identity_exemption(self, hits):
        """Observe identity hits, then demote only the top-K values per
        kind (1 email, 2 IPs). Anything else that crosses THRESHOLD is
        treated as a leak — multiple emails recurring is more likely to
        be other people's data than a second user identity.
        """
        if self.identity is None:
            return hits
        # First pass: observe every identity-kind hit so threshold-
        # crossing values qualify within the same turn.
        for h in hits:
            kind = KIND_FOR_HIT.get(h.name)
            if kind and h.raw:
                try:
                    self.identity.observe(kind, h.raw)
                except Exception as e:
                    log.warning("identity observe failed: %s", e)
        # Single fetch of the qualified set per kind, post-observe.
        try:
            qualified = self.identity.qualified_set()
        except Exception as e:
            log.warning("identity qualified_set failed: %s", e)
            return hits
        # Second pass: demote only values present in the qualified set.
        out = []
        for h in hits:
            kind = KIND_FOR_HIT.get(h.name)
            if kind and h.raw:
                norm = h.raw.strip().lower() if kind == "email" else h.raw.strip()
                if norm in qualified.get(kind, ()):
                    out.append(replace(h, category="user_identity", weight=0.05))
                    continue
            out.append(h)
        return out

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
    def _summary(hits, tier1: float, tier2: float, sensitivity: float,
                 ir: intent_mod.IntentResult | None = None) -> str:
        if not hits and sensitivity < 0.15:
            return "No sensitive content detected."
        parts: list[str] = []
        pii_hits = [h for h in hits
                    if not h.category.startswith("destructive:")
                    and h.category != "user_identity"]
        dcg_hits = [h for h in hits if h.category.startswith("destructive:")]
        identity_hits = [h for h in hits if h.category == "user_identity"]
        if pii_hits:
            parts.append("Detected " + _top_names(pii_hits))
        if dcg_hits:
            parts.append("destructive command(s): " + _top_names(dcg_hits))
        if identity_hits:
            parts.append(f"recognised user identity ×{len(identity_hits)} (exempt)")
        if tier2 >= 0.5:
            parts.append(f"semantic model flagged sensitive content (p={tier2:.2f})")
        if not parts:
            parts.append(f"low-confidence semantic signal (p={tier2:.2f})")
        if ir is not None and ir.intent in intent_mod.DEMOTED:
            parts.append(f"demoted to low (intent={ir.intent})")
        return ". ".join(parts) + "."


def _top_names(hits, k: int = 3) -> str:
    seen: dict[str, int] = {}
    for h in hits:
        seen[h.name] = seen.get(h.name, 0) + 1
    top = sorted(seen.items(), key=lambda kv: -kv[1])[:k]
    return ", ".join(f"{n.replace('_', ' ')} ×{c}" for n, c in top)


def default_paths() -> tuple[str, str]:
    base = os.environ.get("WARDEN_MODEL_DIR", "/models")
    return os.path.join(base, "bpe.json"), os.path.join(base, "lstm.pt")
