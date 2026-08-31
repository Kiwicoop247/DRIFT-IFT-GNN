"""
stage6_train/train_graph.py — graph-level clean(TjFree)-vs-trojan(TjIn)
classification training loop.

Requires `run_pipeline.py --design <NAME> --variant tjfree` to have been run
for every design used here (produces outputs/<NAME>__tjfree/hw2vec/). This is
the complement to stage6_train/train.py's node-level task: same 14-dim
per-node features, pooled via global_mean_pool into one label per design.

BCEWithLogitsLoss with pos_weight from the training pool. Early stop on
validation F1 (patience=10). Saves outputs/gnn/checkpoints/sage_graph_best.pt
and outputs/gnn/train_log_graph.json.
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
from stage6_train.dataset import IFTGraphDataset
from stage6_train.model_graph import build_graph_model
from config.pipeline_config import OUTPUTS_DIR

CKPT_DIR = OUTPUTS_DIR / "gnn" / "checkpoints"
LOG_PATH = OUTPUTS_DIR / "gnn" / "train_log_graph.json"


def _epoch(model, loader, criterion, optim, device, train: bool):
    model.train() if train else model.eval()
    losses, all_p, all_y = [], [], []
    ctx = torch.enable_grad() if train else torch.no_grad()
    with ctx:
        for batch in loader:
            batch = batch.to(device)
            logits = model(batch.x, batch.edge_index, batch.batch)
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=100)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--batch-size", type=int, default=4)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    ap.add_argument("--patience", type=int, default=10)
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    print(f"[stage6-graph] device={args.device} epochs={args.epochs}")
    ds = IFTGraphDataset()
    print(f"[stage6-graph] loaded {len(ds)} graphs, skipped {len(ds.skipped)}: {ds.skipped}")
    if len(ds) < 4:
        print("[stage6-graph] too few graphs to train — run --variant tjfree for more designs first")
        return

    train_data, val_data = ds.split(val_frac=0.2, seed=args.seed)
    train_names = sorted({d.design_name for d in train_data})
    val_names   = sorted({d.design_name for d in val_data})
    print(f"[stage6-graph] train={len(train_data)} graphs ({len(train_names)} designs)  "
          f"val={len(val_data)} graphs ({len(val_names)} designs)")
    print(f"[stage6-graph] val designs: {val_names}")

    pos_w = ds.pos_weight(train_data).to(args.device)
    print(f"[stage6-graph] pos_weight={pos_w.item():.2f}")

    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
    val_loader   = DataLoader(val_data,   batch_size=args.batch_size, shuffle=False)

    model = build_graph_model().to(args.device)
    optim = torch.optim.Adam(model.parameters(), lr=args.lr)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_w)

    CKPT_DIR.mkdir(parents=True, exist_ok=True)
    ckpt_path = CKPT_DIR / "sage_graph_best.pt"

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
                "model": "sage_graph",
                "state_dict": model.state_dict(),
                "epoch": epoch,
                "val_f1": va_f1,
                "val_auroc": va_auc,
                "train_designs": train_names,
                "val_designs": val_names,
                "args": vars(args),
            }, ckpt_path)
        else:
            no_improve += 1
            if no_improve >= args.patience:
                print(f"  early stop at epoch {epoch} (best={best_epoch} f1={best_f1:.3f})")
                break

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "w") as f:
        json.dump({"best_epoch": best_epoch, "best_val_f1": best_f1,
                   "history": history, "ckpt": str(ckpt_path)}, f, indent=2)
    print(f"[stage6-graph] best val_f1={best_f1:.3f} @ epoch {best_epoch}  ckpt={ckpt_path}")


if __name__ == "__main__":
    main()
