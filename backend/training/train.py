"""Token-level training: BPE → char-CNN + word features → BiLSTM → CRF.

Outputs land in $WARDEN_MODEL_DIR (default /models):
    bpe.json
    lstm.pt
    training_data.csv
    metrics.json
    tokenized_cache.pt          (skipped on subsequent runs with same data)
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import time
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset

from warden.bpe import BPETokenizer, PAD_ID
from warden.char_vocab import MAX_CHARS, chars_to_ids
from warden.features import N_FEATURES, feature_vec
from warden.lstm import MAX_LEN, LSTMConfig, SensitivityLSTM, save as save_lstm

from . import generate_data


def _log(msg: str) -> None:
    print(msg, flush=True)


# ── Dataset ────────────────────────────────────────────────────────────────

def _spans_from_csv(spans_field: str) -> list[tuple[int, int]]:
    if not spans_field:
        return []
    try:
        return [tuple(s) for s in json.loads(spans_field)]
    except Exception:
        return []


def _token_label(off: tuple[int, int], spans: list[tuple[int, int]]) -> int:
    a, b = off
    if b <= a:
        return 0
    for ss, ee in spans:
        if a < ee and ss < b:
            return 1
    return 0


def _tokenize_dataset(
    csv_path: Path, tokenizer: BPETokenizer, cache_path: Path,
) -> dict:
    """Tokenize the CSV once and cache the resulting tensors.

    Cache key = (csv_size, csv_mtime, vocab_size, len(tokenizer.merges),
                 first/last vocab entry).  Cheap, good enough.
    """
    stat = csv_path.stat()
    cache_key = hashlib.sha1(
        f"{stat.st_size}-{int(stat.st_mtime)}-{tokenizer.vocab_size}-"
        f"{len(tokenizer.merges)}".encode()
    ).hexdigest()

    if cache_path.exists():
        try:
            blob = torch.load(str(cache_path), weights_only=False)
            if blob.get("key") == cache_key:
                _log(f"[train] reusing tokenized cache {cache_path}")
                return blob
        except Exception as e:
            _log(f"[train] cache load failed ({e}) — re-tokenizing")

    _log(f"[train] tokenizing dataset (cache miss) → {cache_path}")
    ids_all, chars_all, feats_all, tags_all, mask_all, doc_all = [], [], [], [], [], []
    n = 0
    t0 = time.time()
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            text  = row["text"]
            label = int(row["label"])
            spans = _spans_from_csv(row.get("spans", "[]"))
            ids, offsets, surfaces = tokenizer.encode_with_offsets(text, max_len=MAX_LEN)
            tags = [_token_label(off, spans) for off in offsets]
            chars = [chars_to_ids(s, MAX_CHARS) for s in surfaces]
            feats = [feature_vec(s) for s in surfaces]
            mask  = [int(i != PAD_ID) for i in ids]

            ids_all.append(ids)
            chars_all.append(chars)
            feats_all.append(feats)
            tags_all.append(tags)
            mask_all.append(mask)
            doc_all.append(label)
            n += 1
            if n % 2500 == 0:
                _log(f"[train]   tokenized {n} rows ({time.time()-t0:.0f}s)")

    blob = {
        "key": cache_key,
        "ids":   torch.tensor(ids_all,   dtype=torch.long),
        "chars": torch.tensor(chars_all, dtype=torch.long),
        "feats": torch.tensor(feats_all, dtype=torch.float32),
        "tags":  torch.tensor(tags_all,  dtype=torch.long),
        "mask":  torch.tensor(mask_all,  dtype=torch.bool),
        "doc":   torch.tensor(doc_all,   dtype=torch.long),
    }
    torch.save(blob, str(cache_path))
    _log(f"[train] tokenized {n} rows in {time.time()-t0:.0f}s — cached")
    return blob


class TensorDS(Dataset):
    def __init__(self, blob: dict, indices: list[int]) -> None:
        self.b = blob
        self.idx = indices

    def __len__(self) -> int:
        return len(self.idx)

    def __getitem__(self, i: int):
        j = self.idx[i]
        return (
            self.b["ids"][j],
            self.b["chars"][j],
            self.b["feats"][j],
            self.b["tags"][j],
            self.b["mask"][j],
            self.b["doc"][j],
        )


def _read_csv_texts(csv_path: Path) -> list[str]:
    with csv_path.open() as f:
        return [r["text"] for r in csv.DictReader(f)]


def _split3(rows, val_ratio=0.10, test_ratio=0.10):
    n = len(rows)
    n_test = max(1, int(n * test_ratio))
    n_val  = max(1, int(n * val_ratio))
    return rows[n_test + n_val:], rows[n_test:n_test + n_val], rows[:n_test]


# ── Metrics ────────────────────────────────────────────────────────────────

def _binary_metrics(preds: list[int], labels: list[int]) -> dict:
    tp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 1)
    tn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 0)
    fp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 0)
    fn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 1)
    n  = max(len(preds), 1)
    acc  = (tp + tn) / n
    prec = tp / max(tp + fp, 1)
    rec  = tp / max(tp + fn, 1)
    f1   = 2 * prec * rec / max(prec + rec, 1e-9)
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn, "n": n}


def _evaluate(model, loader, device) -> tuple[float, dict, dict]:
    """Returns (loss, doc-level metrics, token-level metrics)."""
    model.eval()
    loss_sum, total_seqs = 0.0, 0
    doc_preds: list[int] = []
    doc_labels: list[int] = []
    tok_preds: list[int] = []
    tok_labels: list[int] = []
    with torch.no_grad():
        for ids, chars, feats, tags, mask, doc in loader:
            ids   = ids.to(device);   chars = chars.to(device); feats = feats.to(device)
            tags  = tags.to(device);  mask  = mask.to(device);  doc   = doc.to(device)
            loss = model.loss(ids, chars, feats, tags, mask)
            loss_sum += loss.item() * ids.size(0)
            total_seqs += ids.size(0)
            paths = model.decode(ids, chars, feats, mask)
            for b, path in enumerate(paths):
                # token-level
                m = mask[b].tolist()
                lbl = tags[b].tolist()
                for t, mt, lt in zip(path, m, lbl):
                    if mt:
                        tok_preds.append(int(t))
                        tok_labels.append(int(lt))
                # doc-level: any token predicted positive
                doc_preds.append(int(any(t == 1 for t in path)))
                doc_labels.append(int(doc[b].item()))
    return (
        loss_sum / max(total_seqs, 1),
        _binary_metrics(doc_preds, doc_labels),
        _binary_metrics(tok_preds, tok_labels),
    )


# ── W&B integration (optional) ─────────────────────────────────────────────

class _WandbRunner:
    def __init__(self, enabled: bool, project: str, run_name: str | None,
                 entity: str | None, config: dict):
        self.run = None
        if not enabled:
            _log("[wandb] disabled")
            return
        try:
            import wandb  # type: ignore
        except ImportError:
            _log("[wandb] requested but `wandb` not installed — running without it.")
            return
        try:
            self.run = wandb.init(
                project=project, entity=entity, name=run_name,
                config=config, reinit="finish_previous",
            )
            _log(f"[wandb] run url: {getattr(self.run, 'url', '?')}")
        except Exception as e:
            _log(f"[wandb] init failed ({e}) — continuing without it.")
            self.run = None

    @property
    def active(self) -> bool: return self.run is not None
    def log(self, payload, step=None):
        if self.run is None: return
        try: self.run.log(payload, step=step)
        except Exception as e: _log(f"[wandb] log failed ({e})")
    def summary(self, payload):
        if self.run is None: return
        try:
            for k, v in payload.items(): self.run.summary[k] = v
        except Exception: pass
    def save_artifact(self, paths, name="warden-model"):
        if self.run is None: return
        try:
            import wandb  # type: ignore
            art = wandb.Artifact(name, type="model")
            for p in paths:
                if p.exists(): art.add_file(str(p))
            self.run.log_artifact(art)
        except Exception as e: _log(f"[wandb] artifact upload failed ({e})")
    def finish(self):
        if self.run is None: return
        try: self.run.finish()
        except Exception: pass


# ── Training ───────────────────────────────────────────────────────────────

def train_model(
    csv_path: Path, out_dir: Path,
    vocab_size: int, epochs: int, batch_size: int, lr: float, seed: int,
    wandb_runner: _WandbRunner | None = None,
) -> dict:
    random.seed(seed); torch.manual_seed(seed)

    _log(f"[train] loading corpus from {csv_path}")
    texts = _read_csv_texts(csv_path)
    _log(f"[train] corpus size: {len(texts)} samples")

    out_dir.mkdir(parents=True, exist_ok=True)
    bpe_path = out_dir / "bpe.json"

    # Reuse existing BPE tokenizer if present — retraining is O(n²×vocab)
    # and takes hours on large corpora.  The vocabulary is stable across runs.
    if bpe_path.exists():
        _log(f"[train] reusing existing BPE tokenizer ({bpe_path})")
        tokenizer = BPETokenizer.load(str(bpe_path))
        _log(f"[train] vocab size: {tokenizer.vocab_size}")
    else:
        _log(f"[train] training BPE tokenizer (target vocab={vocab_size})")
        t0 = time.time()
        tokenizer = BPETokenizer.train(texts, vocab_size=vocab_size)
        _log(f"[train] BPE done — vocab size {tokenizer.vocab_size} in {time.time()-t0:.0f}s")
        tokenizer.save(bpe_path)

    blob = _tokenize_dataset(csv_path, tokenizer, out_dir / "tokenized_cache.pt")
    n = blob["ids"].shape[0]
    rows = list(range(n))
    random.shuffle(rows)
    train_idx, val_idx, test_idx = _split3(rows)
    _log(f"[train] split — train={len(train_idx)} val={len(val_idx)} test={len(test_idx)}")

    train_loader = DataLoader(TensorDS(blob, train_idx), batch_size=batch_size, shuffle=True)
    val_loader   = DataLoader(TensorDS(blob, val_idx),   batch_size=batch_size)
    test_loader  = DataLoader(TensorDS(blob, test_idx),  batch_size=batch_size)

    cfg = LSTMConfig(vocab_size=tokenizer.vocab_size)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    _log(f"[train] device: {device}")
    model = SensitivityLSTM(cfg).to(device)
    optim = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-5)

    if wandb_runner and wandb_runner.active:
        wandb_runner.summary({
            "vocab_size": tokenizer.vocab_size, "samples": n,
            "train_size": len(train_idx), "val_size": len(val_idx),
            "test_size": len(test_idx), "device": device,
            "params": sum(p.numel() for p in model.parameters()),
        })

    history = []
    best_f1, best_state = -1.0, None
    global_step = 0

    for epoch in range(1, epochs + 1):
        model.train()
        loss_sum, seen = 0.0, 0
        epoch_start = time.time()
        for batch_i, (ids, chars, feats, tags, mask, doc) in enumerate(train_loader):
            ids   = ids.to(device);   chars = chars.to(device); feats = feats.to(device)
            tags  = tags.to(device);  mask  = mask.to(device)
            optim.zero_grad()
            loss = model.loss(ids, chars, feats, tags, mask)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            optim.step()
            loss_sum += loss.item() * ids.size(0); seen += ids.size(0)
            global_step += 1

            if (batch_i + 1) % 50 == 0:
                _log(f"[train]   epoch {epoch} batch {batch_i+1}/{len(train_loader)} "
                     f"running_loss={loss_sum/max(seen,1):.4f}")
                if wandb_runner and wandb_runner.active:
                    wandb_runner.log({"batch/loss": loss.item()}, step=global_step)

        train_loss = loss_sum / max(seen, 1)
        val_loss, doc_m, tok_m = _evaluate(model, val_loader, device)
        epoch_time = time.time() - epoch_start

        _log(
            f"[train] epoch {epoch}/{epochs}  ({epoch_time:.1f}s)  "
            f"train loss={train_loss:.4f}  val loss={val_loss:.4f}  "
            f"DOC acc={doc_m['accuracy']:.3f} prec={doc_m['precision']:.3f} "
            f"rec={doc_m['recall']:.3f} f1={doc_m['f1']:.3f}  "
            f"TOK acc={tok_m['accuracy']:.3f} prec={tok_m['precision']:.3f} "
            f"rec={tok_m['recall']:.3f} f1={tok_m['f1']:.3f}"
        )
        history.append({
            "epoch": epoch, "epoch_time_s": epoch_time,
            "train_loss": train_loss, "val_loss": val_loss,
            "doc": doc_m, "tok": tok_m,
        })
        if wandb_runner and wandb_runner.active:
            wandb_runner.log({
                "epoch": epoch, "epoch/epoch_time_s": epoch_time,
                "train/loss": train_loss, "val/loss": val_loss,
                **{f"val_doc/{k}": v for k, v in doc_m.items()},
                **{f"val_tok/{k}": v for k, v in tok_m.items()},
            }, step=global_step)

        if doc_m["f1"] > best_f1:
            best_f1 = doc_m["f1"]
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
        _log(f"[train] restored best-val checkpoint (val DOC f1={best_f1:.3f})")

    test_loss, test_doc, test_tok = _evaluate(model, test_loader, device)
    _log(
        f"[train] TEST  loss={test_loss:.4f}  "
        f"DOC acc={test_doc['accuracy']:.3f} prec={test_doc['precision']:.3f} "
        f"rec={test_doc['recall']:.3f} f1={test_doc['f1']:.3f}  "
        f"(tp={test_doc['tp']} tn={test_doc['tn']} fp={test_doc['fp']} fn={test_doc['fn']})  "
        f"TOK acc={test_tok['accuracy']:.3f} prec={test_tok['precision']:.3f} "
        f"rec={test_tok['recall']:.3f} f1={test_tok['f1']:.3f}"
    )

    lstm_path = out_dir / "lstm.pt"
    save_lstm(model, lstm_path)
    metrics = {
        "history": history,
        "vocab_size": tokenizer.vocab_size, "samples": n,
        "split": {"train": len(train_idx), "val": len(val_idx), "test": len(test_idx)},
        "device": device, "best_val_doc_f1": best_f1,
        "test_loss": test_loss, "test_doc": test_doc, "test_tok": test_tok,
        "params": sum(p.numel() for p in model.parameters()),
    }
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    _log(f"[train] saved tokenizer → {bpe_path}")
    _log(f"[train] saved model     → {lstm_path}")

    if wandb_runner and wandb_runner.active:
        wandb_runner.summary({
            "test/loss": test_loss,
            **{f"test_doc/{k}": v for k, v in test_doc.items()},
            **{f"test_tok/{k}": v for k, v in test_tok.items()},
            "best_val_doc_f1": best_f1,
        })
        wandb_runner.save_artifact([bpe_path, lstm_path, out_dir / "metrics.json"])
    return metrics


def _merge_csvs(synth: Path, real: Path, out: Path) -> None:
    """Merge synthetic + real-annotated CSVs, shuffle, write to out."""
    rows: list[dict] = []
    for p in (synth, real):
        with p.open(encoding="utf-8") as f:
            rows.extend(csv.DictReader(f))
    random.shuffle(rows)
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["text", "label", "spans"])
        w.writeheader()
        w.writerows(rows)
    _log(f"[train] merged {len(rows)} rows ({synth.name} + {real.name}) → {out}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--data", type=Path, default=None)
    p.add_argument("--real-data", type=Path, default=None,
                   help="CSV of real annotated events; merged with synthetic data before training")
    p.add_argument("--out", type=Path,
                   default=Path(os.environ.get("WARDEN_MODEL_DIR", "/models")))
    p.add_argument("--n-samples", type=int, default=8000)
    p.add_argument("--vocab-size", type=int, default=4000)
    p.add_argument("--epochs", type=int, default=4)
    p.add_argument("--batch-size", type=int, default=64)
    p.add_argument("--lr", type=float, default=2e-3)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--real-only", action="store_true",
                   help="Skip synthetic data generation; use --data as the sole training source")
    p.add_argument("--force", action="store_true")
    p.add_argument("--wandb", dest="wandb", action="store_true",
                   default=os.environ.get("WARDEN_WANDB", "0") == "1")
    p.add_argument("--no-wandb", dest="wandb", action="store_false")
    p.add_argument("--wandb-project", default=os.environ.get("WANDB_PROJECT", "llm-warden"))
    p.add_argument("--wandb-entity",  default=os.environ.get("WANDB_ENTITY"))
    p.add_argument("--wandb-run-name", default=os.environ.get("WANDB_RUN_NAME"))
    args = p.parse_args()

    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.data or (out_dir / "training_data.csv")

    if args.real_only:
        if not csv_path.exists():
            _log(f"[train] --real-only set but {csv_path} not found — aborting")
            return
        _log(f"[train] real-only mode — using {csv_path} (no synthetic data)")
    elif args.force or not csv_path.exists():
        generate_data.generate(args.n_samples, csv_path, seed=args.seed)
    else:
        _log(f"[train] reusing existing dataset {csv_path}")

    if args.real_data and args.real_data.exists():
        merged_path = out_dir / "merged_training_data.csv"
        _merge_csvs(csv_path, args.real_data, merged_path)
        csv_path = merged_path
    elif args.real_data:
        _log(f"[train] --real-data {args.real_data} not found, skipping merge")

    if (
        not args.force
        and (out_dir / "bpe.json").exists()
        and (out_dir / "lstm.pt").exists()
    ):
        _log("[train] model files already present — skipping (use --force to retrain)")
        return

    runner = _WandbRunner(
        enabled=args.wandb, project=args.wandb_project,
        run_name=args.wandb_run_name, entity=args.wandb_entity,
        config={
            "csv_path": str(csv_path), "vocab_size": args.vocab_size,
            "epochs": args.epochs, "batch_size": args.batch_size,
            "lr": args.lr, "seed": args.seed, "max_len": MAX_LEN,
            "arch": "embed+charCNN+features → BiLSTM → CRF",
        },
    )
    try:
        train_model(
            csv_path=csv_path, out_dir=out_dir,
            vocab_size=args.vocab_size, epochs=args.epochs,
            batch_size=args.batch_size, lr=args.lr, seed=args.seed,
            wandb_runner=runner,
        )
    finally:
        runner.finish()


if __name__ == "__main__":
    main()
