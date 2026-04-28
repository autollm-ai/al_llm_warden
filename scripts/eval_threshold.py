#!/usr/bin/env python3
"""Re-evaluate the trained model on the test split at multiple
doc-level thresholds — no retraining.

Loads:
    models/lstm.pt
    models/bpe.json (config only — embedded in lstm.pt)
    models/tokenized_cache.pt

Reproduces the same 80/10/10 split (seed=7) used at training time, runs
the model on the test split, and reports DOC-level metrics for several
thresholds applied to `max-over-tokens softmax(emissions)[..., 1]` —
the same `doc_score` the proxy already uses at inference.
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

import torch
from torch.utils.data import DataLoader

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from warden.lstm import load as load_lstm  # noqa: E402
from training.train import TensorDS, _binary_metrics, _split3  # noqa: E402


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--model", type=Path, default=ROOT / "models" / "lstm.pt")
    p.add_argument("--cache", type=Path, default=ROOT / "models" / "tokenized_cache.pt")
    p.add_argument("--seed",  type=int, default=7)
    p.add_argument("--batch-size", type=int, default=128)
    p.add_argument("--thresholds", type=str,
                   default="0.50,0.40,0.30,0.25,0.20,0.15,0.10,0.05")
    args = p.parse_args()

    if not args.model.exists():
        sys.exit(f"missing {args.model}")
    if not args.cache.exists():
        sys.exit(f"missing {args.cache} — run training first or seed it from another box")

    random.seed(args.seed); torch.manual_seed(args.seed)
    blob = torch.load(str(args.cache), weights_only=False)
    n = blob["ids"].shape[0]
    rows = list(range(n))
    random.shuffle(rows)
    _, _, test_idx = _split3(rows)
    print(f"loaded cache: {n} rows; test split = {len(test_idx)}")

    model = load_lstm(str(args.model))
    model.eval()

    loader = DataLoader(TensorDS(blob, test_idx), batch_size=args.batch_size)

    all_scores: list[float] = []
    all_doc:    list[int]   = []
    all_tags:   list[int]   = []
    all_decode: list[int]   = []
    with torch.no_grad():
        for ids, chars, feats, tags, mask, doc in loader:
            em = model.emissions(ids, chars, feats)
            marg = model.crf.marginal_pos(em, mask)               # [B, L]
            doc_score = marg.max(dim=1).values                     # [B]
            all_scores.extend(doc_score.tolist())
            all_doc.extend(doc.int().tolist())
            # also collect Viterbi-any-tag for the comparison row
            paths = model.crf.decode(em, mask)
            all_decode.extend(int(any(t == 1 for t in p)) for p in paths)
            all_tags.extend([])  # not used here

    print()
    # Baseline row: what training-time _evaluate reported.
    m_v = _binary_metrics(all_decode, all_doc)
    print(f"  baseline (Viterbi any-tag=1)     "
          f"acc={m_v['accuracy']:.3f}  prec={m_v['precision']:.3f}  "
          f"rec={m_v['recall']:.3f}  f1={m_v['f1']:.3f}  "
          f"tp={m_v['tp']} tn={m_v['tn']} fp={m_v['fp']} fn={m_v['fn']}")
    print()

    print(f"  {'threshold':>10}  {'acc':>5}  {'prec':>5}  {'rec':>5}  {'f1':>5}    confusion")
    print(f"  {'-'*10}  {'-'*5}  {'-'*5}  {'-'*5}  {'-'*5}    {'-'*30}")
    best_f1 = -1.0
    best_thr = None
    for thr_s in args.thresholds.split(","):
        thr = float(thr_s)
        preds = [int(s >= thr) for s in all_scores]
        m = _binary_metrics(preds, all_doc)
        print(f"  {thr:>10.3f}  {m['accuracy']:>5.3f}  {m['precision']:>5.3f}  "
              f"{m['recall']:>5.3f}  {m['f1']:>5.3f}    "
              f"tp={m['tp']} tn={m['tn']} fp={m['fp']} fn={m['fn']}")
        if m["f1"] > best_f1:
            best_f1, best_thr = m["f1"], thr

    print()
    print(f"  ► best F1 = {best_f1:.3f} at threshold = {best_thr}")

    # Score distribution for the false-negative samples.
    print()
    print("  Doc-score histogram on label=1 samples (where the model is uncertain):")
    pos_scores = [s for s, l in zip(all_scores, all_doc) if l == 1]
    buckets = [0.0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.8, 1.001]
    for lo, hi in zip(buckets, buckets[1:]):
        c = sum(1 for s in pos_scores if lo <= s < hi)
        bar = "█" * (c * 60 // max(len(pos_scores), 1))
        print(f"  [{lo:.2f}, {hi:.2f})  {c:>5}  {bar}")
    print(f"  TOTAL label=1 in test: {len(pos_scores)}")

    # Production label-level breakdown — what the dashboard would show.
    print()
    print("  Production labels (from doc_score alone, before regex blend):")
    from warden.classifier import label_for
    label_counts = {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    label_pos_counts = {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for s, l in zip(all_scores, all_doc):
        lb = label_for(s)
        label_counts[lb] += 1
        if l == 1:
            label_pos_counts[lb] += 1
    print(f"  {'label':>10}  {'all docs':>10}  {'label=1 docs':>14}")
    for lb in ["clean", "low", "medium", "high", "critical"]:
        print(f"  {lb:>10}  {label_counts[lb]:>10}  {label_pos_counts[lb]:>14}")
    flagged = sum(label_pos_counts[l] for l in ["low", "medium", "high", "critical"])
    print(f"  any non-clean label catches {flagged}/{len(pos_scores)} label=1 docs "
          f"({100*flagged/max(len(pos_scores),1):.1f}%)")

    # Combined tier-1 (regex) + tier-2 (LSTM) — what production actually uses.
    print()
    print("  Combining with regex tier-1 (production blend):")
    import csv
    from warden.regex_engine import scan as regex_scan
    from warden.classifier import Classifier, label_for
    csv_rows: list[tuple[str, int]] = []
    csv_path = ROOT / "models" / "training_data.csv"
    if not csv_path.exists():
        print(f"  ⚠ {csv_path} missing — skip combined eval")
        return
    with csv_path.open() as f:
        for r in csv.DictReader(f):
            csv_rows.append((r["text"], int(r["label"])))
    # Re-derive the test split.
    random.seed(args.seed); torch.manual_seed(args.seed)
    rows = list(range(len(csv_rows)))
    random.shuffle(rows)
    _, _, test_idx = _split3(rows)
    blend_w = Classifier().tier2_weight  # 0.55

    blended: list[float] = []
    for j, score2 in zip(test_idx, all_scores):
        text, _label = csv_rows[j]
        _, score1 = regex_scan(text)
        base = max(score1, score2)
        boost = (1.0 - base) * min(score1, score2) * blend_w
        blended.append(min(1.0, base + boost))

    print(f"  {'label':>10}  {'all docs':>10}  {'label=1 docs':>14}")
    blend_label_counts = {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    blend_pos_counts   = {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for s, l in zip(blended, all_doc):
        lb = label_for(s)
        blend_label_counts[lb] += 1
        if l == 1:
            blend_pos_counts[lb] += 1
    for lb in ["clean", "low", "medium", "high", "critical"]:
        print(f"  {lb:>10}  {blend_label_counts[lb]:>10}  {blend_pos_counts[lb]:>14}")
    bflag = sum(blend_pos_counts[l] for l in ["low", "medium", "high", "critical"])
    print(f"  combined non-clean recall = {bflag}/{len(pos_scores)} "
          f"= {100*bflag/max(len(pos_scores),1):.1f}%")
    # FP count
    bfp = sum(1 for s, l in zip(blended, all_doc) if l == 0 and label_for(s) != "clean")
    print(f"  combined false positives  = {bfp}/{sum(1 for l in all_doc if l == 0)}")


if __name__ == "__main__":
    main()
