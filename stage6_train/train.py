"""
stage6_train/train.py — node-level GNN training loop.

BCEWithLogitsLoss with pos_weight from training pool. Mini-batch by graph.
Early stop on validation F1 (patience=10). Saves best checkpoint to
outputs/gnn/checkpoints/<model>_best.pt and a metrics_train.json log.
"""

import sys
import json
import argparse
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch_geometric.loader import DataLoader
from sklearn.metrics import f1_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).parent.parent))
from stage6_train.dataset import IFTNodeDataset
from stage6_train.model import build_model
from config.pipeline_config import OUTPUTS_DIR, discover_designs

CKPT_DIR = OUTPUTS_DIR / "gnn" / "checkpoints"
LOG_PATH = OUTPUTS_DIR / "gnn" / "train_log.json"


def _epoch(model, loader, criterion, optim, device, train: bool):
    model.train() if train else model.eval()
    losses, all_p, all_y = [], [], []
    ctx = torch.enable_grad() if train else torch.no_grad()
    with ctx:
        for batch in loader:
            batch = batch.to(device)
            logits = model(batch.x, batch.edge_index)
            loss = criterion(logits, batch.y)
            if train:
                optim.zero_grad()
                loss.backward()
                optim.step()
            losses.append(float(loss.item()))
            all_p.append(torch.sigmoid(logits).detach().cpu().numpy())
            all_y.append(batch.y.detach().cpu().numpy())
    p = np.concatenate(all_p)
    y = np.concatenate(all_y).astype(int)
    pred = (p >= 0.5).astype(int)
    f1 = f1_score(y, pred, zero_division=0)
    try:
        auroc = roc_auc_score(y, p) if y.sum() > 0 and y.sum() < len(y) else float("nan")
    except ValueError:
        auroc = float("nan")
    return float(np.mean(losses)), f1, auroc


def _run_fold(ds, train_data, val_data, args, fold_name=None):
    """Trains one model on (train_data, val_data), saves a checkpoint and log
    named for `fold_name` (None -> unsuffixed, the plain random-split run).
    Returns the log dict that was written.
    """
    suffix = f"_{fold_name}" if fold_name else ""
    ckpt_path = CKPT_DIR / f"{args.model}{suffix}_best.pt"
    log_path = LOG_PATH.parent / f"train_log{suffix}.json"

    train_names = [d.design_name for d in train_data]
    val_names   = [d.design_name for d in val_data]
    print(f"[stage6] fold={fold_name or 'random'} train={len(train_data)} val={len(val_data)}")
    print(f"[stage6] val designs: {val_names}")

    pos_w = ds.pos_weight(train_data).to(args.device)
    print(f"[stage6] pos_weight={pos_w.item():.2f}")

    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
    val_loader   = DataLoader(val_data,   batch_size=args.batch_size, shuffle=False)

    model = build_model(args.model).to(args.device)
    optim = torch.optim.Adam(model.parameters(), lr=args.lr)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_w)

    CKPT_DIR.mkdir(parents=True, exist_ok=True)

    best_f1, best_epoch, no_improve = -1.0, -1, 0
    history = []

    for epoch in range(1, args.epochs + 1):
        tr_loss, tr_f1, tr_auc = _epoch(model, train_loader, criterion, optim, args.device, train=True)
        va_loss, va_f1, va_auc = _epoch(model, val_loader,   criterion, optim, args.device, train=False)
        history.append({"epoch": epoch, "train_loss": tr_loss, "train_f1": tr_f1, "train_auroc": tr_auc,
                        "val_loss": va_loss, "val_f1": va_f1, "val_auroc": va_auc})
        print(f"  epoch {epoch:3d}  tr_loss={tr_loss:.4f} tr_f1={tr_f1:.3f} tr_auc={tr_auc:.3f}  "
              f"va_loss={va_loss:.4f} va_f1={va_f1:.3f} va_auc={va_auc:.3f}")

        if va_f1 > best_f1:
            best_f1, best_epoch, no_improve = va_f1, epoch, 0
            torch.save({
                "model": args.model,
                "state_dict": model.state_dict(),
                "epoch": epoch,
                "val_f1": va_f1,
                "val_auroc": va_auc,
                "train_designs": train_names,
                "val_designs": val_names,
                "fold": fold_name,
                "args": vars(args),
            }, ckpt_path)
        else:
            no_improve += 1
            if no_improve >= args.patience:
                print(f"  early stop at epoch {epoch} (best={best_epoch} f1={best_f1:.3f})")
                break

    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = {"fold": fold_name, "best_epoch": best_epoch, "best_val_f1": best_f1,
           "history": history, "ckpt": str(ckpt_path)}
    with open(log_path, "w") as f:
        json.dump(log, f, indent=2)
    print(f"[stage6] fold={fold_name or 'random'} best val_f1={best_f1:.3f} @ epoch {best_epoch}  ckpt={ckpt_path}")
    return log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["sage", "gcn"], default="sage")
    ap.add_argument("--epochs", type=int, default=100)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--batch-size", type=int, default=4)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    ap.add_argument("--patience", type=int, default=10)
    ap.add_argument("--split-mode", choices=["random", "holdout", "kfold"], default="random",
                     help="'random': fixed-seed 80/20 design split, no held-out test set "
                          "(smoke test). 'holdout': fixed-seed 3-way design split (default "
                          "60/20/20) with a genuinely held-out test set never touched by "
                          "training or checkpoint selection — see --val-frac/--test-frac. "
                          "'kfold': k-fold CV, randomly partitioned at the design level — "
                          "see --k.")
    ap.add_argument("--val-frac", type=float, default=0.2,
                     help="Validation fraction for --split-mode holdout (default: 0.2)")
    ap.add_argument("--test-frac", type=float, default=0.2,
                     help="Held-out test fraction for --split-mode holdout (default: 0.2)")
    ap.add_argument("--k", type=int, default=5,
                     help="Number of folds for --split-mode kfold (default: 5)")
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    designs = discover_designs()

    print(f"[stage6] device={args.device}  model={args.model}  epochs={args.epochs}  "
          f"split-mode={args.split_mode}  ({len(designs)} designs)")
    ds = IFTNodeDataset(designs=designs)
    print(f"[stage6] loaded {len(ds)} designs, skipped {ds.skipped}")

    if args.split_mode == "random":
        train_data, val_data = ds.split(val_frac=0.2, seed=args.seed)
        _run_fold(ds, train_data, val_data, args, fold_name=None)
        return

    if args.split_mode == "holdout":
        # 3-way split: test_data is deliberately never passed into _run_fold
        # (it only trains on train_data/val_data) — since those designs then
        # appear in neither the checkpoint's train_designs nor val_designs,
        # evaluate.py's existing "unseen" bucket picks them up automatically
        # as a true, never-touched generalization set.
        train_data, val_data, test_data = ds.split3(
            val_frac=args.val_frac, test_frac=args.test_frac, seed=args.seed)
        print(f"[stage6] holdout split: train={len(train_data)} val={len(val_data)} "
              f"test={len(test_data)}")
        print(f"[stage6] held-out test designs: {[d.design_name for d in test_data]}")
        _run_fold(ds, train_data, val_data, args, fold_name="holdout")
        return

    if args.split_mode == "kfold":
        fold_logs = {}
        for train_data, val_data, fold_name in ds.kfold_splits(k=args.k, seed=args.seed):
            log = _run_fold(ds, train_data, val_data, args, fold_name=fold_name)
            fold_logs[fold_name] = log

        vals = [l["best_val_f1"] for l in fold_logs.values()]
        agg = {
            "split_mode": "kfold",
            "k": args.k,
            "folds": fold_logs,
            "mean_val_f1": float(np.mean(vals)) if vals else None,
            "std_val_f1": float(np.std(vals)) if vals else None,
        }
        agg_path = LOG_PATH.parent / "train_log_kfold_summary.json"
        agg_path.parent.mkdir(parents=True, exist_ok=True)
        with open(agg_path, "w") as f:
            json.dump(agg, f, indent=2)
        print(f"[stage6] kfold mean val_f1={agg['mean_val_f1']} std={agg['std_val_f1']}  summary={agg_path}")
        return


if __name__ == "__main__":
    main()
