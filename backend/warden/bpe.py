"""Pure-Python BPE tokenizer.

Trained from a corpus of strings; serialised as JSON. Trades raw speed for
zero external dependencies — fast enough for our 200-token classifier.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# Reserved IDs.
PAD_ID = 0
UNK_ID = 1
BOS_ID = 2
EOS_ID = 3
RESERVED = {"<pad>": PAD_ID, "<unk>": UNK_ID, "<bos>": BOS_ID, "<eos>": EOS_ID}

# Word boundary marker — common BPE convention.
END_OF_WORD = "</w>"

_WORD_RE = re.compile(r"\S+")


def _split_words(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


@dataclass
class BPETokenizer:
    vocab: dict[str, int]
    merges: list[tuple[str, str]]

    @property
    def vocab_size(self) -> int:
        return len(self.vocab)

    @classmethod
    def train(cls, corpus: list[str], vocab_size: int = 4000, min_freq: int = 2) -> "BPETokenizer":
        word_freq: Counter[tuple[str, ...]] = Counter()
        for line in corpus:
            for w in _split_words(line):
                # Each word becomes a tuple of chars + end-of-word marker.
                tokens = tuple(list(w) + [END_OF_WORD])
                word_freq[tokens] += 1

        vocab: dict[str, int] = dict(RESERVED)
        # Seed vocab with all single chars / END_OF_WORD.
        for word in word_freq:
            for ch in word:
                if ch not in vocab:
                    vocab[ch] = len(vocab)

        merges: list[tuple[str, str]] = []
        target = max(vocab_size, len(vocab) + 1)
        while len(vocab) < target:
            pairs: Counter[tuple[str, str]] = Counter()
            for word, freq in word_freq.items():
                for a, b in zip(word, word[1:]):
                    pairs[(a, b)] += freq
            if not pairs:
                break
            (best_a, best_b), best_count = pairs.most_common(1)[0]
            if best_count < min_freq:
                break
            merged_token = best_a + best_b
            if merged_token in vocab:
                # Already present — just record the merge order.
                merges.append((best_a, best_b))
                continue
            vocab[merged_token] = len(vocab)
            merges.append((best_a, best_b))

            new_freq: Counter[tuple[str, ...]] = Counter()
            for word, freq in word_freq.items():
                new_word: list[str] = []
                i = 0
                while i < len(word):
                    if i + 1 < len(word) and word[i] == best_a and word[i + 1] == best_b:
                        new_word.append(merged_token)
                        i += 2
                    else:
                        new_word.append(word[i])
                        i += 1
                new_freq[tuple(new_word)] += freq
            word_freq = new_freq

        return cls(vocab=vocab, merges=merges)

    def _bpe_word(self, word: str) -> list[str]:
        if not word:
            return []
        tokens: list[str] = list(word) + [END_OF_WORD]
        for a, b in self.merges:
            i = 0
            merged_token = a + b
            new_tokens: list[str] = []
            while i < len(tokens):
                if i + 1 < len(tokens) and tokens[i] == a and tokens[i + 1] == b:
                    new_tokens.append(merged_token)
                    i += 2
                else:
                    new_tokens.append(tokens[i])
                    i += 1
            tokens = new_tokens
        return tokens

    def encode(self, text: str, max_len: int | None = None) -> list[int]:
        ids: list[int] = []
        for w in _split_words(text):
            for piece in self._bpe_word(w):
                ids.append(self.vocab.get(piece, UNK_ID))
        if max_len is not None:
            if len(ids) >= max_len:
                ids = ids[:max_len]
            else:
                ids = ids + [PAD_ID] * (max_len - len(ids))
        return ids

    def encode_with_offsets(
        self, text: str, max_len: int | None = None
    ) -> tuple[list[int], list[tuple[int, int]], list[str]]:
        """Encode plus per-token (start, end) char offsets into `text` and the
        token's surface string. Used by the CRF / char-CNN training paths.

        Offsets are relative to the *original* `text`. PAD positions get
        `(0, 0)` and an empty surface string.
        """
        out_ids: list[int] = []
        out_offsets: list[tuple[int, int]] = []
        out_strs: list[str] = []
        lower = text.lower()
        for m in _WORD_RE.finditer(lower):
            word = m.group(0)
            word_start = m.start()
            pieces = self._bpe_word(word)
            char_idx = 0
            for piece in pieces:
                if piece.endswith(END_OF_WORD):
                    surface = piece[:-len(END_OF_WORD)]
                else:
                    surface = piece
                a = word_start + char_idx
                b = a + len(surface)
                char_idx += len(surface)
                out_ids.append(self.vocab.get(piece, UNK_ID))
                out_offsets.append((a, b))
                out_strs.append(piece)
        if max_len is not None:
            if len(out_ids) >= max_len:
                out_ids = out_ids[:max_len]
                out_offsets = out_offsets[:max_len]
                out_strs = out_strs[:max_len]
            else:
                pad = max_len - len(out_ids)
                out_ids = out_ids + [PAD_ID] * pad
                out_offsets = out_offsets + [(0, 0)] * pad
                out_strs = out_strs + [""] * pad
        return out_ids, out_offsets, out_strs

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps({"vocab": self.vocab, "merges": self.merges}))

    @classmethod
    def load(cls, path: str | Path) -> "BPETokenizer":
        data = json.loads(Path(path).read_text())
        return cls(
            vocab=data["vocab"],
            merges=[tuple(m) for m in data["merges"]],
        )
