"""Hand-crafted per-token word features fed alongside the BPE embedding.

For each BPE token (its surface string) we emit a small fixed-size vector of
shallow signals — uppercase-ness, presence of digits / punctuation,
length bucket, etc. These give the BiLSTM cheap features that are hard for
a 64-d embedding to learn from a small synthetic corpus.
"""
from __future__ import annotations

N_FEATURES = 9


def feature_vec(token_str: str) -> list[float]:
    """Map a token's surface string to N_FEATURES floats in [0, 1]."""
    s = token_str
    if s.endswith("</w>"):
        s = s[:-4]
    if not s:
        return [0.0] * N_FEATURES
    return [
        float(s.isdigit()),                                  # 0: pure digits
        float(any(c.isdigit() for c in s)),                  # 1: contains a digit
        float(s.isupper()),                                  # 2: all upper
        float(any(c.isupper() for c in s)),                  # 3: contains upper
        float(any(not c.isalnum() and not c.isspace() for c in s)),  # 4: any punct
        float("@" in s),                                     # 5: at-sign
        float("-" in s),                                     # 6: dash
        float("." in s),                                     # 7: dot
        min(len(s), 20) / 20.0,                              # 8: length bucket
    ]
