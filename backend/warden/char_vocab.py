"""Character-level vocabulary for the per-token char-CNN.

Reserved IDs:
    0  CHAR_PAD — token shorter than MAX_CHARS, or BPE end-of-word piece.
    1  CHAR_UNK — anything outside the ASCII printable range.
"""
from __future__ import annotations

import string

CHAR_PAD = 0
CHAR_UNK = 1
MAX_CHARS = 16

_ALPHABET = string.ascii_lowercase + string.digits + string.punctuation + " "
CHAR_VOCAB: dict[str, int] = {c: i + 2 for i, c in enumerate(_ALPHABET)}
CHAR_VOCAB_SIZE = len(CHAR_VOCAB) + 2  # + PAD + UNK


def chars_to_ids(token: str, max_chars: int = MAX_CHARS) -> list[int]:
    s = token[:-4] if token.endswith("</w>") else token
    s = s[:max_chars]
    ids = [CHAR_VOCAB.get(c, CHAR_UNK) for c in s]
    if len(ids) < max_chars:
        ids = ids + [CHAR_PAD] * (max_chars - len(ids))
    return ids
