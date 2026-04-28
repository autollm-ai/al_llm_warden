# Model architecture — `SensitivityLSTM` (NER-style)

End-to-end pipeline for the tier-2 sensitivity classifier. Each step below
points at the **exact file and line range** that implements it, so we can
edit in-place when we change the architecture.

> **TL;DR.** Outbound text → BPE tokens (with char offsets) →
> **(word-embed concat word-features) → 1-D Conv over BPE tokens** (the
> sequence-level CNN), then concat with a parallel **per-token char-CNN**,
> then BiLSTM → linear emissions → **CRF** for token-level
> sensitive/non-sensitive tagging. Document score = max over non-pad
> tokens of P(tag=1). Trained with token-level labels derived from the
> spans of `_sensitive_sentence` outputs.

---

## 1. Data path overview

```
raw text  ──► BPE tokenizer (with char offsets)
                  │ ids[B, L=200]   surfaces[B, L]   offsets[B, L]
                  │
                  ├─► nn.Embedding(V, 64)        word_emb [B,L,64]
                  │
                  ├─► hand-crafted features      feats   [B,L,9]
                  │
                  │     concat([word_emb, feats])  → [B, L, 73]
                  │     Dropout(0.2)
                  │             │
                  │             ▼
                  │     Conv1d(73 → 64, k=3, pad=1)  + ReLU       (seq-level CNN)
                  │             │ seq [B, L, 64]
                  │             │
                  │             │   ┌──── char IDs [B, L, 16]
                  │             │   ▼
                  │             │   nn.Embedding(C, 16)   char_emb [B*L, 16, 16]
                  │             │   Conv1d(16 → 32, k=3)  + ReLU
                  │             │   max-pool over chars   → char_pool [B, L, 32]
                  │             │
                  │             ▼
                  │     concat([seq, char_pool])  → [B, L, 96]
                  │             │
                  │             ▼
                  │     BiLSTM(96 → 96, 1L)       out [B, L, 192]
                  │             │
                  │             ▼
                  │     Linear(192 → 2)           emissions [B, L, 2]
                  │             │
                  │             ▼
                  │     CRF (2 tags)
                  │
                  ┌────────────┼────────────────┐
                  ▼            ▼                ▼
          loss = -log P(y|x)  Viterbi      softmax → P(tag=1)
                              best path     max over tokens → doc score
```

---

## 2. Layer-by-layer breakdown with file:line references

| # | Component | Where (file:line) | Shape in → out | Notes |
|---|-----------|-------------------|----------------|-------|
| 1 | `LSTMConfig` dataclass | `backend/warden/lstm.py:34–66` | — | Holds *all* knobs (word, char, feature, BiLSTM, CRF) so config travels with the weights. |
| 2 | `MAX_LEN = 200` | `backend/warden/lstm.py:30` | — | BPE-token cap per request. |
| 3 | `N_TAGS = 2` | `backend/warden/lstm.py:31` | — | Binary token tags. Set to >2 to support multi-class spans. |
| 4 | BPE tokenizer with offsets | `backend/warden/bpe.py:124–162` | str → (ids, char-offsets, surfaces) | Used by training (to derive token labels) and inference (for char-CNN inputs). |
| 5 | `nn.Embedding(V, 64)` (word) | `backend/warden/lstm.py:79–81` | `[B,L]` → `[B,L,64]` | `padding_idx=PAD_ID`. |
| 6 | `nn.Embedding(C, 16)` (char) | `backend/warden/lstm.py:84–86` | `[B,L,C]` → `[B,L,C,16]` | `padding_idx=CHAR_PAD`. C ≈ 95 + 2. |
| 7 | `Conv1d(16 → 32, k=3, p=1)` | `backend/warden/lstm.py:87–91` | `[B*L,16,C]` → `[B*L,32,C]` | Convolves character embeddings within each token. |
| 8 | ReLU + max-pool over chars | `backend/warden/lstm.py:131–134` | `[B*L,32,C]` → `[B*L,32]` | Captures token-shape features (digits, punct mixes). |
| 9 | Reshape back to per-token | `backend/warden/lstm.py:135` | `[B*L,32]` → `[B,L,32]` | |
| 10 | Word features (`features.py`) | `backend/warden/features.py:15–32` | str → 9 floats | digits / upper / punct / @ / - / . / length-bucket. |
| 11 | Concat: word ‖ char ‖ feat | `backend/warden/lstm.py:137` | `[B,L,64+32+9]` → `[B,L,105]` | |
| 12 | Input dropout (0.2) | `backend/warden/lstm.py:101, 138` | `[B,L,105]` | |
| 13 | BiLSTM(105 → 96, 1 layer) | `backend/warden/lstm.py:104–113` | `[B,L,105]` → `[B,L,192]` | Bidirectional, batch_first. |
| 14 | Emission linear `192 → 2` | `backend/warden/lstm.py:114` | `[B,L,192]` → `[B,L,2]` | Per-token tag scores. |
| 15 | Linear-chain CRF | `backend/warden/crf.py` | `[B,L,2]` → loss / paths / marginals | NLL loss for training; Viterbi for hard tags; softmax-over-emissions for the inference doc score. |
| 16 | Save / load | `backend/warden/lstm.py:166–179` | — | Keeps `LSTMConfig.to_dict()` next to the weights — old checkpoints (without char/feature fields) load with sensible defaults via `LSTMConfig.from_dict`. |

---

## 3. Parameter count (defaults `vocab=4000, embed=64, hidden=96`)

```
embedding.weight                 (4000, 64)    256 000
char_emb.weight                  (~97, 16)       1 552
char_conv.weight + bias                          1 568
lstm.weight_ih_l0                (384, 105)     40 320       ← input_dim now 105
lstm.weight_hh_l0                (384, 96)      36 864
lstm.bias_ih_l0 / bias_hh_l0     (384,)            768
lstm.* _reverse                  (same)         77 952
emit.weight + bias               (2, 192)+(2)      386
crf.start_transitions            (2,)               2
crf.end_transitions              (2,)               2
crf.transitions                  (2, 2)             4
─────────────────────────────────────────────────────
TOTAL                                          ≈ 415 418
```

(Exact total prints at training time as `params: …`.)

---

## 4. Training pipeline (where each step lives)

| Step | File:line | What happens |
|------|-----------|--------------|
| Synthetic CSV generator | `backend/training/generate_data.py:230–262` (`_make_sample`) | Now also emits **`spans`** — char ranges that came from `_sensitive_sentence`. Used to derive token-level labels. |
| CSV writer (3 cols: text, label, spans) | `backend/training/generate_data.py:266–278` (`generate`) | |
| Read texts (for BPE training) | `backend/training/train.py:_read_csv_texts` | |
| Train BPE tokenizer | `backend/warden/bpe.py:33–80` (`BPETokenizer.train`) — invoked at `backend/training/train.py:235` | |
| Tokenise + cache | `backend/training/train.py:42–98` (`_tokenize_dataset`) | Emits `tokenized_cache.pt` keyed on (csv size, mtime, vocab size, # merges). Subsequent runs skip the slow BPE pass. |
| Per-token label derivation | `backend/training/train.py:36–45` (`_token_label`) | A BPE token gets label 1 if its char span overlaps any sensitive sentence span. |
| Train / val / test split | `backend/training/train.py:122–127` (`_split3`) | 80 / 10 / 10. |
| Build model | `backend/training/train.py:248–251` | `SensitivityLSTM(LSTMConfig(vocab_size=…))`. |
| Optimiser & loss | `backend/training/train.py:252` + `model.loss(...)` (`backend/warden/lstm.py:147–148`) | AdamW(lr=2e-3, wd=1e-5); CRF NLL loss. |
| Training loop | `backend/training/train.py:267–290` | Per-batch fwd/bwd + grad-clip(5.0); progress every 50 batches. |
| Per-epoch eval | `backend/training/train.py:_evaluate` (`backend/training/train.py:147–177`) | Reports **both** doc-level metrics (any-token-positive) and token-level metrics. |
| Best-checkpoint save | `backend/training/train.py:301–303` | Tracks best-val DOC F1. |
| Final test eval | `backend/training/train.py:309–316` | Single TEST line + `metrics.json`. |
| Save weights | `backend/warden/lstm.py:166–170` (`save`) — invoked at `train.py:319` | `{"config": …, "state": state_dict}`. |
| Inference | `backend/warden/classifier.py:_tier2_score` | Encode → char-ids → features → `model.doc_score(...)` → max-marginal P(sensitive). |

---

## 5. Knobs you can change — and where

| Knob | Default | File:line | Effect |
|------|---------|-----------|--------|
| `MAX_LEN` (BPE token cap) | 200 | `backend/warden/lstm.py:30` | More context, slower training. |
| `embed_dim` (word embed) | 64 | `backend/warden/lstm.py:36` | |
| `hidden_dim` (BiLSTM) | 96 | `backend/warden/lstm.py:37` | |
| `num_layers` (BiLSTM) | 1 | `backend/warden/lstm.py:38` | Stack ≥2 to enable inter-layer dropout. |
| `dropout` | 0.2 | `backend/warden/lstm.py:39` | Applied on the concat input + (with ≥2 layers) inside the BiLSTM. |
| `char_embed_dim` | 16 | `backend/warden/lstm.py:43` | |
| `char_conv_channels` | 32 | `backend/warden/lstm.py:44` | Output of the char-CNN. |
| `char_conv_kernel` | 3 | `backend/warden/lstm.py:45` | Bigger kernel = larger char n-gram receptive field. |
| `char_max` | 16 | `backend/warden/lstm.py:46` | Truncates very long BPE pieces; rare in practice. |
| `n_features` (word feats) | 9 | `backend/warden/features.py:11` | Add a feature ⇒ bump this + add to `feature_vec`. |
| Char alphabet | ASCII printable + space | `backend/warden/char_vocab.py:14` | |
| `n_tags` (CRF tags) | 2 | `backend/warden/lstm.py:48` | Move to BIO-tagging by setting to 3 + relabel. |
| Pooling for doc score | `max` of P(tag=1) | `backend/warden/lstm.py:159–162` | Try mean-of-top-k or threshold counting. |
| Loss | CRF NLL | `backend/warden/crf.py:CRF.forward` | Could swap for label-smoothed CRF. |
| Optimiser / LR | AdamW, 2e-3 | `backend/training/train.py:252` | Add scheduler (`torch.optim.lr_scheduler.OneCycleLR`) here. |
| Grad-clip | 5.0 | `backend/training/train.py:281` | |
| Threshold for "doc positive" | tag-1 anywhere | `backend/training/train.py:170–171` | Change to "≥k tokens" or "max P > τ". |
| Tier-2 blend weight | 0.55 | `backend/warden/classifier.py:Classifier.tier2_weight` | |

---

## 6. Notes on labels & weak supervision

- Token-level labels come from spans the data generator emits — there is
  no human-labelled span data.  Anything inside a `_sensitive_sentence`
  template is positive; everything else is negative.  Subtle *implicit*
  sensitivity (a paragraph about quarterly numbers without obvious entity
  patterns) is NOT in the training signal — that's where the regex tier-1
  is still load-bearing.
- The CRF transition matrix `transitions[i, j]` is 2×2 — it learns that
  positive runs are typically multi-token (e.g. "AKIA…" gets tokenised
  into several BPE pieces; the CRF favours staying in tag=1 across them).
- Doc score at inference time is the **max** marginal P(tag=1) across
  non-pad tokens.  A single high-confidence positive token is enough to
  flag the request; the CRF smoothing makes that signal less noisy than
  the previous sigmoid-on-pooled-vector approach.

---

## 7. How the model is used at runtime

1. mitmproxy intercepts an outbound HTTPS request → `backend/proxy/addon.py:Warden.request`.
2. JSON body is flattened to a single string (`backend/proxy/addon.py:_flatten_payload`).
3. `Classifier.classify` runs:
   - **Tier-1 regex** (`backend/warden/regex_engine.py:scan`) → list of hits + saturating score.
   - **Tier-2 NER-style model** (`backend/warden/classifier.py:_tier2_score`):
     - `tokenizer.encode_with_offsets` → ids + offsets + surfaces
     - `chars_to_ids` (`char_vocab.py`) and `feature_vec` (`features.py`) per token
     - `model.doc_score(ids, chars, feats, mask)` → max over softmax(emissions)[..,1] on non-pad tokens
4. Final score = `max(t1, t2) + (1 − max) × min × 0.55`.
5. Event written to SQLite via `backend/warden/database.py:EventStore.insert`.
6. The proxy adds `X-Warden-Scanned: 1` + `X-Warden-Label: <label>` headers.

---

Ready for review — point at any line and we can change it.
