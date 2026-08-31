"""
stage6_train/evaluate.py — load best checkpoint and emit per-design metrics,
top-k FP/FN tables, and a confusion-matrix figure.
"""

import sys
import json
import argparse
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)

sys.path.insert(0, str(Path(__file__).parent.parent))
from stage6_train.dataset import IFTNodeDataset, _load_design
from stage6_train.model import build_model
from config.pipeline_config import OUTPUTS_DIR, discover_designs

CKPT_DIR    = OUTPUTS_DIR / "gnn" / "checkpoints"
METRICS_PATH = OUTPUTS_DIR / "gnn" / "metrics.json"
FIG_DIR     = OUTPUTS_DIR / "gnn" / "figures"


def _design_metrics(y, p, thresh=0.5):
    pred = (p >= thresh).astype(int)
    out = {
        "support": int(len(y)),
        "n_pos":   int(y.sum()),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall":    float(recall_score(y, pred, zero_division=0)),
        "f1":        float(f1_score(y, pred, zero_division=0)),
    }
    try:
        out["auroc"] = float(roc_auc_score(y, p)) if 0 < y.sum() < len(y) else None
    except ValueError:
        out["auroc"] = None
    return out


def _best_threshold(y, p, steps=100):
    """Sweep thresholds in (0,1) and return the one maximizing F1, plus that F1."""
    if y.sum() == 0 or y.sum() == len(y):
        return 0.5, float(f1_score(y, (p >= 0.5).astype(int), zero_division=0))
    best_t, best_f1 = 0.5, -1.0
    for i in range(1, steps):
        t = i / steps
        f1 = f1_score(y, (p >= t).astype(int), zero_division=0)
        if f1 > best_f1:
            best_t, best_f1 = t, f1
    return best_t, best_f1


def _top_k(probs_by_design, names_by_design, y_by_design, k=10, mode="fp"):
    rows = []
    for design, probs in probs_by_design.items():
        names = names_by_design[design]
        y = y_by_design[design]
        for i, (pr, yi, nm) in enumerate(zip(probs, y, names)):
            if mode == "fp" and yi == 0:
                rows.append((float(pr), design, nm))
            elif mode == "fn" and yi == 1:
                rows.append((float(pr), design, nm))
    rows.sort(reverse=(mode == "fp"))
    out = []
    for pr, design, nm in rows[:k]:
        out.append({"design": design, "node": nm, "score": pr})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["sage", "gcn"], default="sage")
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    ap.add_argument("--thresh", type=float, default=0.5)
    ap.add_argument("--fold", default=None,
                     help="Fold-suffixed checkpoint to load — 'holdout' for --split-mode holdout, "
                          "or 'fold0'..'fold{k-1}' for --split-mode kfold. Omit for the plain "
                          "random-split checkpoint.")
    ap.add_argument("--calibrate", action="store_true",
                     help="Sweep per-design thresholds to report the F1-maximizing threshold alongside the fixed one.")
    args = ap.parse_args()

    suffix = f"_{args.fold}" if args.fold else ""
    ckpt = torch.load(CKPT_DIR / f"{args.model}{suffix}_best.pt", map_location=args.device, weights_only=False)
    model = build_model(args.model).to(args.device)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    train_set = set(ckpt.get("train_designs", []))
    val_set   = set(ckpt.get("val_designs", []))

    designs = discover_designs()
    ds = IFTNodeDataset(designs=designs)
    per_design = {}
    probs_by_design, names_by_design, y_by_design = {}, {}, {}

    with torch.no_grad():
        for d in ds.data_list:
            meta_path = OUTPUTS_DIR / d.design_name / "hw2vec" / "metadata.json"
            try:
                meta = json.loads(meta_path.read_text())
                names = meta.get("node_names", [])
            except Exception:
                names = [f"n{i}" for i in range(d.num_nodes)]

            x  = d.x.to(args.device)
            ei = d.edge_index.to(args.device)
            logits = model(x, ei)
            probs = torch.sigmoid(logits).cpu().numpy()
            y = d.y.cpu().numpy().astype(int)

            split = "train" if d.design_name in train_set else ("val" if d.design_name in val_set else "unseen")
            m = _design_metrics(y, probs, thresh=args.thresh)
            m["split"] = split
            if args.calibrate:
                best_t, best_f1 = _best_threshold(y, probs)
                m["calibrated_threshold"] = best_t
                m["calibrated_f1"] = best_f1
            per_design[d.design_name] = m
            probs_by_design[d.design_name] = probs
            names_by_design[d.design_name] = names
            y_by_design[d.design_name]     = y

    val_designs = [n for n, m in per_design.items() if m["split"] == "val"]
    val_y = np.concatenate([y_by_design[n] for n in val_designs]) if val_designs else np.array([])
    val_p = np.concatenate([probs_by_design[n] for n in val_designs]) if val_designs else np.array([])
    val_pred = (val_p >= args.thresh).astype(int) if len(val_y) else np.array([])

    aggregate = {
        "val_macro_f1":    float(np.mean([m["f1"] for n, m in per_design.items() if m["split"] == "val"])) if val_designs else None,
        "val_micro_f1":    float(f1_score(val_y, val_pred, zero_division=0)) if len(val_y) else None,
        "val_micro_auroc": float(roc_auc_score(val_y, val_p)) if len(val_y) and 0 < val_y.sum() < len(val_y) else None,
        "n_train": len(train_set), "n_val": len(val_set),
    }
    if args.calibrate and val_designs:
        aggregate["val_macro_f1_calibrated"] = float(np.mean(
            [per_design[n]["calibrated_f1"] for n in val_designs]))
        pooled_t, pooled_f1 = _best_threshold(val_y, val_p) if len(val_y) else (0.5, None)
        aggregate["val_micro_f1_calibrated"] = pooled_f1
        aggregate["val_micro_threshold_calibrated"] = pooled_t

    top_fp = _top_k(probs_by_design, names_by_design, y_by_design, k=15, mode="fp")
    top_fn = _top_k(
        {k: 1 - v for k, v in probs_by_design.items()},  # invert so top = lowest prob trojans
        names_by_design,
        y_by_design,
        k=15, mode="fn",
    )
    for r in top_fn:
        r["score"] = 1 - r["score"]  # restore actual prob

    out = {
        "model": args.model,
        "fold": args.fold,
        "checkpoint": str(CKPT_DIR / f"{args.model}{suffix}_best.pt"),
        "best_epoch": ckpt.get("epoch"),
        "best_val_f1_train_time": ckpt.get("val_f1"),
        "aggregate": aggregate,
        "per_design": per_design,
        "top_false_positives": top_fp,
        "top_false_negatives": top_fn,
    }
    metrics_path = METRICS_PATH.parent / f"metrics{suffix}.json"
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(out, indent=2))
    print(f"[stage6] wrote {metrics_path}")

    # Dump per-node predictions so figure scripts can be re-run without
    # re-doing inference. One .npz with two arrays per design: probs_<d>, y_<d>,
    # plus a JSON sidecar listing splits.
    preds_path = OUTPUTS_DIR / "gnn" / f"predictions_{args.model}{suffix}.npz"
    np_kwargs = {}
    splits = {}
    for d_name, probs in probs_by_design.items():
        safe = d_name.replace("-", "_")
        np_kwargs[f"probs__{safe}"] = probs.astype(np.float32)
        np_kwargs[f"y__{safe}"]     = y_by_design[d_name].astype(np.int8)
        splits[d_name] = per_design[d_name]["split"]
    np.savez_compressed(preds_path, **np_kwargs)
    (OUTPUTS_DIR / "gnn" / f"predictions_{args.model}{suffix}_splits.json").write_text(
        json.dumps(splits, indent=2)
    )
    print(f"[stage6] wrote {preds_path}")
    print(f"  val macro-F1 = {aggregate['val_macro_f1']}  micro-F1 = {aggregate['val_micro_f1']}  AUROC = {aggregate['val_micro_auroc']}")
    if args.calibrate:
        print(f"  calibrated: macro-F1 = {aggregate.get('val_macro_f1_calibrated')}  "
              f"micro-F1 = {aggregate.get('val_micro_f1_calibrated')} @ t={aggregate.get('val_micro_threshold_calibrated')}")

    # Confusion matrix figure (val only)
    if len(val_y):
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            cm = confusion_matrix(val_y, val_pred, labels=[0, 1])
            FIG_DIR.mkdir(parents=True, exist_ok=True)
            fig, ax = plt.subplots(figsize=(4, 4))
            im = ax.imshow(cm, cmap="Blues")
            ax.set_xticks([0, 1]); ax.set_xticklabels(["clean", "trojan"])
            ax.set_yticks([0, 1]); ax.set_yticklabels(["clean", "trojan"])
            ax.set_xlabel("predicted"); ax.set_ylabel("true")
            ax.set_title(f"{args.model.upper()} — val confusion matrix")
            for i in range(2):
                for j in range(2):
                    ax.text(j, i, str(cm[i, j]), ha="center", va="center",
                            color="white" if cm[i, j] > cm.max() / 2 else "black")
            fig.colorbar(im, ax=ax, fraction=0.046)
            fig.tight_layout()
            fig_path = FIG_DIR / f"confusion_matrix_{args.model}{suffix}.png"
            fig.savefig(fig_path, dpi=120)
            plt.close(fig)
            print(f"[stage6] saved {fig_path}")
        except Exception as e:
            print(f"[stage6] skipped confusion-matrix figure: {e}")


if __name__ == "__main__":
    main()
