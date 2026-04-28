"""Minimal linear-chain Conditional Random Field.

Provides:
    forward(emissions, tags, mask) → mean negative log-likelihood (loss)
    decode(emissions, mask)        → list[list[int]]  (Viterbi best paths)
    marginal_pos(emissions, mask)  → [B, L]  P(tag=1 | emissions)

Parameters (`num_tags` defaults to 2 — non-sensitive vs sensitive):
    start_transitions[K]
    end_transitions[K]
    transitions[K, K]   transitions[i, j] = score of moving from i → j
"""
from __future__ import annotations

import torch
import torch.nn as nn


class CRF(nn.Module):
    def __init__(self, num_tags: int = 2) -> None:
        super().__init__()
        self.num_tags = num_tags
        self.start_transitions = nn.Parameter(torch.empty(num_tags))
        self.end_transitions   = nn.Parameter(torch.empty(num_tags))
        self.transitions       = nn.Parameter(torch.empty(num_tags, num_tags))
        self.reset_parameters()

    def reset_parameters(self) -> None:
        nn.init.uniform_(self.start_transitions, -0.1, 0.1)
        nn.init.uniform_(self.end_transitions,   -0.1, 0.1)
        nn.init.uniform_(self.transitions,       -0.1, 0.1)

    # ── helpers ─────────────────────────────────────────────────────────
    def _validate(self, emissions: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        # emissions [B, L, K], mask [B, L] (bool or 0/1)
        if mask.dtype != torch.bool:
            mask = mask.bool()
        # Caller guarantees mask[:, 0] is all True (we always start with a
        # real token at position 0 because PAD goes to the end).
        return mask

    # ── log-likelihood (numerator – denominator) ────────────────────────
    def _numerator(self, emissions: torch.Tensor, tags: torch.Tensor,
                   mask: torch.Tensor) -> torch.Tensor:
        B, L, _ = emissions.shape
        # Score of the gold path under the emissions + transitions.
        score = self.start_transitions[tags[:, 0]] \
                + emissions[torch.arange(B), 0, tags[:, 0]]
        for i in range(1, L):
            m = mask[:, i].float()
            trans = self.transitions[tags[:, i - 1], tags[:, i]]
            emit  = emissions[torch.arange(B), i, tags[:, i]]
            score = score + (trans + emit) * m
        # Add the end transition for the last *real* token of every row.
        seq_lens = mask.sum(dim=1).long() - 1     # [B]
        last_tags = tags[torch.arange(B), seq_lens]
        score = score + self.end_transitions[last_tags]
        return score                                # [B]

    def _denominator(self, emissions: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        B, L, K = emissions.shape
        # log-sum-exp over all paths via the forward algorithm.
        alpha = self.start_transitions.unsqueeze(0) + emissions[:, 0]   # [B, K]
        for i in range(1, L):
            broadcast_emit  = emissions[:, i].unsqueeze(1)              # [B, 1, K]
            broadcast_alpha = alpha.unsqueeze(2)                        # [B, K, 1]
            broadcast_trans = self.transitions.unsqueeze(0)             # [1, K, K]
            scores = broadcast_alpha + broadcast_trans + broadcast_emit # [B, K, K]
            new_alpha = torch.logsumexp(scores, dim=1)                  # [B, K]
            m = mask[:, i].unsqueeze(1).float()
            alpha = new_alpha * m + alpha * (1 - m)
        alpha = alpha + self.end_transitions.unsqueeze(0)
        return torch.logsumexp(alpha, dim=1)                            # [B]

    def forward(self, emissions: torch.Tensor, tags: torch.Tensor,
                mask: torch.Tensor) -> torch.Tensor:
        mask = self._validate(emissions, mask)
        num = self._numerator(emissions, tags, mask)
        den = self._denominator(emissions, mask)
        return -(num - den).mean()

    # ── Viterbi ─────────────────────────────────────────────────────────
    def decode(self, emissions: torch.Tensor, mask: torch.Tensor) -> list[list[int]]:
        mask = self._validate(emissions, mask)
        B, L, K = emissions.shape

        score = self.start_transitions.unsqueeze(0) + emissions[:, 0]   # [B, K]
        history: list[torch.Tensor] = []
        for i in range(1, L):
            broadcast_score = score.unsqueeze(2)                        # [B, K, 1]
            broadcast_emit  = emissions[:, i].unsqueeze(1)              # [B, 1, K]
            broadcast_trans = self.transitions.unsqueeze(0)             # [1, K, K]
            all_scores = broadcast_score + broadcast_trans + broadcast_emit  # [B, K, K]
            new_score, idx = all_scores.max(dim=1)                      # idx: [B, K]
            history.append(idx)
            m = mask[:, i].unsqueeze(1).float()
            score = new_score * m + score * (1 - m)
        score = score + self.end_transitions.unsqueeze(0)

        seq_lens = mask.sum(dim=1).long()
        best_paths: list[list[int]] = []
        for b in range(B):
            n = int(seq_lens[b].item())
            if n == 0:
                best_paths.append([])
                continue
            best_last = int(score[b].argmax().item())
            path = [best_last]
            for i in range(n - 1, 0, -1):
                # history[i-1] tells us the best previous tag for tag `path[-1]` at step i
                best_last = int(history[i - 1][b, path[-1]].item())
                path.append(best_last)
            path.reverse()
            best_paths.append(path)
        return best_paths

    # ── Soft per-token marginals (for inference scores) ─────────────────
    def marginal_pos(self, emissions: torch.Tensor, mask: torch.Tensor) -> torch.Tensor:
        """Approximate posterior P(tag=1 | x) per token via emissions softmax.

        We use a softmax over emissions rather than full forward-backward
        because (a) the proxy only needs a smoothly-changing score, not the
        true marginal, and (b) it keeps inference fast on CPU.
        """
        mask = self._validate(emissions, mask)
        probs = torch.softmax(emissions, dim=-1)
        return probs[..., 1] * mask.float()
