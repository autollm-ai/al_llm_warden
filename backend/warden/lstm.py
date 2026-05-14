"""Tier-2 sensitivity model.

Architecture (NER-style):

    BPE token IDs ─► Embedding ─┐
                                ├─► concat ─► BiLSTM ─► Linear emit ─► CRF
    chars per token ► Char-CNN ─┤
    word features  ────────────┘

Trained with token-level labels: each BPE position is labelled 1 if its
character span overlaps a sensitive sentence, else 0. The CRF lets the model
condition each tag on the previous one (e.g. once we're inside a credit-card
span, the next token is much more likely to also be sensitive).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import torch
import torch.nn as nn

from .bpe import PAD_ID
from .char_vocab import CHAR_PAD, CHAR_VOCAB_SIZE, MAX_CHARS
from .crf import CRF
from .features import N_FEATURES

MAX_LEN = 200
# Sliding-window stride for texts longer than MAX_LEN. Adjacent windows
# overlap by (MAX_LEN - WINDOW_STRIDE) tokens so a sensitive span that
# straddles a boundary still lands fully inside at least one window.
# 50-token overlap covers typical secrets (cards, keys, SSNs are well under
# 50 BPE tokens) while keeping per-token redundancy to ~1.3× instead of 4×.
WINDOW_STRIDE = 150
# Hard cap on input tokens fed to the windower. Beyond this we truncate —
# vanishing-gradient already dilutes long-range signal inside each 200-tok
# window, so adding more windows is mostly compute, and an unbounded loop
# is an easy OOM/DoS vector when a huge body lands on the proxy.
MAX_TEXT_LEN = 4096
# Per-document aggregation over windows: mean of top-k window scores. Less
# brittle to a single spuriously-high token than pure max, while still
# firing on a needle in a haystack. With k=5 the trigger threshold becomes
# 1/(2k) = 0.1 (vs 0.5 for the old max aggregation).
TOPK_WINDOWS = 5
N_TAGS = 2  # 0 = non-sensitive, 1 = sensitive


@dataclass
class LSTMConfig:
    vocab_size: int
    embed_dim: int = 64
    hidden_dim: int = 96
    num_layers: int = 1
    dropout: float = 0.2
    max_len: int = MAX_LEN
    # Char-CNN (parallel branch — still needs char IDs as input)
    char_vocab_size: int = CHAR_VOCAB_SIZE
    char_embed_dim:  int = 16
    char_conv_channels: int = 32
    char_conv_kernel:   int = 3
    char_max: int = MAX_CHARS
    # Word features
    n_features: int = N_FEATURES
    # Sequence-level CNN (sits AFTER embedding+features, BEFORE BiLSTM)
    seq_conv_channels: int = 64
    seq_conv_kernel:   int = 3
    # CRF
    n_tags: int = N_TAGS

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in (
            "vocab_size", "embed_dim", "hidden_dim", "num_layers", "dropout",
            "max_len", "char_vocab_size", "char_embed_dim",
            "char_conv_channels", "char_conv_kernel", "char_max",
            "n_features", "seq_conv_channels", "seq_conv_kernel", "n_tags",
        )}

    @classmethod
    def from_dict(cls, d: dict) -> "LSTMConfig":
        # Allow loading old checkpoints that didn't have these fields.
        defaults = cls(vocab_size=d["vocab_size"]).to_dict()
        merged = {**defaults, **d}
        return cls(**merged)


class SensitivityLSTM(nn.Module):
    def __init__(self, config: LSTMConfig) -> None:
        super().__init__()
        self.config = config

        # ── Word embedding ─────────────────────────────────────────────
        self.embedding = nn.Embedding(
            config.vocab_size, config.embed_dim, padding_idx=PAD_ID
        )

        # ── Char-level CNN (parallel branch over chars-per-token) ──────
        self.char_emb = nn.Embedding(
            config.char_vocab_size, config.char_embed_dim, padding_idx=CHAR_PAD
        )
        self.char_conv = nn.Conv1d(
            in_channels=config.char_embed_dim,
            out_channels=config.char_conv_channels,
            kernel_size=config.char_conv_kernel,
            padding=config.char_conv_kernel // 2,
        )

        # ── Sequence-level 1-D CNN over (word-embed ‖ word-features) ───
        # Runs across the BPE-token dimension so each position sees a
        # k-token window of the [embed|feats] vector. Output is
        # concatenated with the per-token char-CNN pool before the BiLSTM.
        self.seq_conv = nn.Conv1d(
            in_channels=config.embed_dim + config.n_features,
            out_channels=config.seq_conv_channels,
            kernel_size=config.seq_conv_kernel,
            padding=config.seq_conv_kernel // 2,
        )

        # BiLSTM input = sequence-conv output ‖ char-CNN pool.
        per_tok_dim = config.seq_conv_channels + config.char_conv_channels

        self.input_dropout = nn.Dropout(config.dropout)

        # ── BiLSTM ─────────────────────────────────────────────────────
        self.lstm = nn.LSTM(
            input_size=per_tok_dim,
            hidden_size=config.hidden_dim,
            num_layers=config.num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=config.dropout if config.num_layers > 1 else 0.0,
        )

        # ── Emission head ─────────────────────────────────────────────
        self.emit = nn.Linear(config.hidden_dim * 2, config.n_tags)

        # ── CRF ───────────────────────────────────────────────────────
        self.crf = CRF(num_tags=config.n_tags)

    # ── feature pipeline ───────────────────────────────────────────────
    def _encode(self, ids: torch.Tensor, chars: torch.Tensor,
                feats: torch.Tensor) -> torch.Tensor:
        """ids[B,L], chars[B,L,C], feats[B,L,F] → [B, L, 2H] (BiLSTM output)."""
        B, L = ids.shape

        # 1) Word embedding.
        word_emb = self.embedding(ids)                          # [B, L, E]

        # 2) Concat word features → 1-D CNN over BPE-token sequence.
        wf = torch.cat([word_emb, feats], dim=-1)               # [B, L, E+F]
        wf = self.input_dropout(wf)
        seq = torch.relu(
            self.seq_conv(wf.transpose(1, 2))                   # [B, E+F, L]
        ).transpose(1, 2)                                       # [B, L, SC]

        # 3) Char-CNN (parallel) — collapse batch+length, conv, max-pool.
        char_emb = self.char_emb(chars.view(B * L, -1))         # [B*L, C, CE]
        char_emb = char_emb.transpose(1, 2)                     # [B*L, CE, C]
        char_act = torch.relu(self.char_conv(char_emb))         # [B*L, OC, C']
        char_pool = char_act.max(dim=-1).values                 # [B*L, OC]
        char_pool = char_pool.view(B, L, -1)                    # [B, L, OC]

        # 4) Concat sequence-CNN output with char-CNN pool, feed BiLSTM.
        x = torch.cat([seq, char_pool], dim=-1)                 # [B, L, SC+OC]
        out, _ = self.lstm(x)                                   # [B, L, 2H]
        return out

    def emissions(self, ids: torch.Tensor, chars: torch.Tensor,
                  feats: torch.Tensor) -> torch.Tensor:
        return self.emit(self._encode(ids, chars, feats))       # [B, L, n_tags]

    # ── training / inference entry points ──────────────────────────────
    def loss(self, ids, chars, feats, tags, mask) -> torch.Tensor:
        return self.crf(self.emissions(ids, chars, feats), tags, mask)

    def decode(self, ids, chars, feats, mask) -> list[list[int]]:
        return self.crf.decode(self.emissions(ids, chars, feats), mask)

    def doc_score(self, ids, chars, feats, mask) -> torch.Tensor:
        """Per-document P(sensitive) ∈ [0, 1] = max over non-PAD tokens of
        the softmax(emissions)[..., 1] (a smooth proxy for "any token is
        sensitive")."""
        em = self.emissions(ids, chars, feats)
        marg = self.crf.marginal_pos(em, mask)                  # [B, L]
        return marg.max(dim=1).values                           # [B]

    # ── back-compat: an old caller might still call forward(ids) with
    # a single tensor. We don't support that path any more; raise loudly.
    def forward(self, *args, **kwargs):
        raise RuntimeError(
            "SensitivityLSTM no longer accepts a single tensor — call "
            "model.emissions(ids, chars, feats) or model.loss(...) instead."
        )


def save(model: SensitivityLSTM, path: str | Path) -> None:
    torch.save(
        {"config": model.config.to_dict(), "state": model.state_dict()},
        str(path),
    )


def load(path: str | Path, device: str = "cpu") -> SensitivityLSTM:
    blob = torch.load(str(path), map_location=device, weights_only=False)
    cfg = LSTMConfig.from_dict(blob["config"])
    model = SensitivityLSTM(cfg)
    model.load_state_dict(blob["state"])
    model.to(device)
    model.eval()
    return model
