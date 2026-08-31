"""
visualize/viz_gnn.py — Thesis figures for the Stage-6 GNN.

Reads:
  outputs/gnn/train_log.json                 — per-epoch loss / F1 / AUROC
  outputs/gnn/metrics.json                   — per-design metrics + top FP/FN
  outputs/gnn/predictions_<model>.npz        — per-node probs + true labels
  outputs/gnn/predictions_<model>_splits.json

Writes (under outputs/gnn/figures/):
  training_curves_<model>.png
  roc_pr_curves_<model>.png
  score_distribution_<model>.png
  calibration_<model>.png
  per_design_f1_<model>.png
  per_design_auroc_<model>.png
  confusion_by_split_<model>.png
  top_errors_<model>.png

Run after stage6_train.evaluate, which now dumps predictions.npz.
"""

from __future__ import annotations

import sys
import json
import argparse
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (
    roc_curve, precision_recall_curve, auc,
    confusion_matrix,
)

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import OUTPUTS_DIR
from visualize.style import apply_thesis_style, color_of, family_of, FAMILY_LABELS, FAMILY_COLORS

GNN_DIR = OUTPUTS_DIR / "gnn"
FIG_DIR = GNN_DIR / "figures"

SPLIT_COLORS = {"train": "#888888", "val": "#117733", "unseen": "#cc6677"}

# Matches the (empty) filename suffix convention in stage6_train/train.py &
# evaluate.py so figures are read from the same files those scripts produced.
CORPUS_SUFFIX = ""


def _load_predictions(model: str):
    npz_path = GNN_DIR / f"predictions_{model}{CORPUS_SUFFIX}.npz"
    splits_path = GNN_DIR / f"predictions_{model}{CORPUS_SUFFIX}_splits.json"
    if not npz_path.exists():
        raise SystemExit(
            f"missing {npz_path}; run stage6_train.evaluate first to dump per-node probs."
        )
    arr = np.load(npz_path)
    splits = json.loads(splits_path.read_text())
    designs = sorted(splits.keys())
    probs, y, design_split = {}, {}, {}
    for d in designs:
        safe = d.replace("-", "_")
        probs[d] = arr[f"probs__{safe}"]
        y[d]     = arr[f"y__{safe}"].astype(int)
        design_split[d] = splits[d]
    return probs, y, design_split


def _concat(probs, y, designs):
    if not designs:
        return np.array([]), np.array([])
    return (
        np.concatenate([probs[d] for d in designs]),
        np.concatenate([y[d]     for d in designs]),
    )


def _load_fold_predictions(model: str, fold_i: int):
    """Load one k-fold fold's predictions.npz + splits.json. Returns None if
    that fold hasn't been evaluated yet."""
    npz_path = GNN_DIR / f"predictions_{model}_fold{fold_i}.npz"
    splits_path = GNN_DIR / f"predictions_{model}_fold{fold_i}_splits.json"
    if not npz_path.exists():
        return None
    arr = np.load(npz_path)
    splits = json.loads(splits_path.read_text())
    probs, y = {}, {}
    for d in splits:
        safe = d.replace("-", "_")
        probs[d] = arr[f"probs__{safe}"]
        y[d]     = arr[f"y__{safe}"].astype(int)
    return probs, y, splits


def _load_kfold_oof(model: str, k: int):
    """Pool out-of-fold predictions across all k folds: each design's
    predictions come from the ONE fold where it was held out (split=="val"),
    so together they cover every design in the corpus exactly once with no
    train leakage — the standard k-fold "out-of-fold" (OOF) prediction set.
    """
    probs, y = {}, {}
    for i in range(k):
        loaded = _load_fold_predictions(model, i)
        if loaded is None:
            continue
        f_probs, f_y, splits = loaded
        for d, sp in splits.items():
            if sp == "val" and d not in probs:
                probs[d] = f_probs[d]
                y[d] = f_y[d]
    return probs, y


# ---------------------------------------------------------------- #
# 1. Training curves                                                #
# ---------------------------------------------------------------- #
def plot_training_curves(model: str):
    log = json.loads((GNN_DIR / f"train_log{CORPUS_SUFFIX}.json").read_text())
    hist = log["history"]
    ep    = [h["epoch"] for h in hist]
    tr_l  = [h["train_loss"]  for h in hist]
    va_l  = [h["val_loss"]    for h in hist]
    tr_f  = [h["train_f1"]    for h in hist]
    va_f  = [h["val_f1"]      for h in hist]
    tr_a  = [h["train_auroc"] for h in hist]
    va_a  = [h["val_auroc"]   for h in hist]
    best  = log.get("best_epoch")

    fig, axes = plt.subplots(1, 3, figsize=(13, 3.6))
    for ax, (tr, va, title, ylim) in zip(
        axes,
        [(tr_l, va_l, "Loss",  None),
         (tr_f, va_f, "F1",    (0, 1)),
         (tr_a, va_a, "AUROC", (0, 1))],
    ):
        ax.plot(ep, tr, label="train", color="#888888", lw=1.6)
        ax.plot(ep, va, label="val",   color="#117733", lw=1.8)
        if best is not None:
            ax.axvline(best, color="#cc6677", lw=1.0, ls="--", alpha=0.7, label=f"best (ep {best})")
        ax.set_xlabel("epoch")
        ax.set_title(title)
        if ylim:
            ax.set_ylim(*ylim)
        ax.legend(loc="best")
    fig.suptitle(f"{model.upper()} training dynamics", y=1.02, fontsize=12, fontweight="bold")
    out = FIG_DIR / f"training_curves_{model}{CORPUS_SUFFIX}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ---------------------------------------------------------------- #
# 1b. k-fold training curves — all folds overlaid on one figure     #
# ---------------------------------------------------------------- #
def plot_training_curves_kfold(model: str, k: int):
    """Overlay all k folds' validation loss/F1/AUROC on one figure,
    color-coded by fold — for comparing fold-to-fold variance at a glance
    instead of flipping between k separate per-fold training_curves PNGs.
    """
    palette = plt.cm.tab10.colors
    fig, axes = plt.subplots(1, 3, figsize=(13, 3.6))
    any_data = False
    for i in range(k):
        log_path = GNN_DIR / f"train_log_fold{i}.json"
        if not log_path.exists():
            continue
        log = json.loads(log_path.read_text())
        hist = log["history"]
        ep   = [h["epoch"]      for h in hist]
        va_l = [h["val_loss"]   for h in hist]
        va_f = [h["val_f1"]     for h in hist]
        va_a = [h["val_auroc"]  for h in hist]
        c = palette[i % len(palette)]
        label = f"fold{i} (best f1={log.get('best_val_f1', 0):.3f})"
        axes[0].plot(ep, va_l, color=c, lw=1.6, label=label)
        axes[1].plot(ep, va_f, color=c, lw=1.6, label=label)
        axes[2].plot(ep, va_a, color=c, lw=1.6, label=label)
        best = log.get("best_epoch")
        if best is not None:
            for ax in axes:
                ax.axvline(best, color=c, lw=0.8, ls="--", alpha=0.4)
        any_data = True
    if not any_data:
        plt.close(fig)
        return None
    for ax, title, ylim in zip(axes, ("Val loss", "Val F1", "Val AUROC"), (None, (0, 1), (0, 1))):
        ax.set_xlabel("epoch")
        ax.set_title(title)
        if ylim:
            ax.set_ylim(*ylim)
    axes[0].legend(loc="best", fontsize=7)
    fig.suptitle(f"{model.upper()} k-fold training dynamics ({k} folds, val only)",
                 y=1.02, fontsize=12, fontweight="bold")
    out = FIG_DIR / f"training_curves_kfold_{model}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ---------------------------------------------------------------- #
# 2. ROC + PR curves                                                #
# ---------------------------------------------------------------- #
def plot_roc_pr(model: str, probs, y, design_split):
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
    for split in ("train", "val", "unseen"):
        designs = [d for d, s in design_split.items() if s == split]
        p, yy = _concat(probs, y, designs)
        if len(yy) == 0 or yy.sum() == 0 or yy.sum() == len(yy):
            continue
        fpr, tpr, _ = roc_curve(yy, p)
        roc_auc = auc(fpr, tpr)
        prec, rec, _ = precision_recall_curve(yy, p)
        pr_auc = auc(rec, prec)
        c = SPLIT_COLORS[split]
        axes[0].plot(fpr, tpr, color=c, lw=1.8, label=f"{split} (AUC={roc_auc:.3f})")
        axes[1].plot(rec, prec, color=c, lw=1.8, label=f"{split} (AUC={pr_auc:.3f})")
    axes[0].plot([0, 1], [0, 1], color="#bbbbbb", lw=1.0, ls="--")
    axes[0].set_xlabel("false-positive rate"); axes[0].set_ylabel("true-positive rate")
    axes[0].set_title("ROC")
    axes[1].set_xlabel("recall"); axes[1].set_ylabel("precision")
    axes[1].set_title("Precision–Recall")
    for ax in axes:
        ax.set_xlim(0, 1); ax.set_ylim(0, 1.02); ax.legend(loc="lower right")
    fig.suptitle(f"{model.upper()} ROC / PR by split", y=1.02, fontsize=12, fontweight="bold")
    out = FIG_DIR / f"roc_pr_curves_{model}{CORPUS_SUFFIX}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_roc_pr_kfold(model: str, k: int):
    """Per-fold ROC/PR curves (val-only, i.e. out-of-fold) overlaid on one
    figure, color-coded by fold."""
    palette = plt.cm.tab10.colors
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
    any_data = False
    for i in range(k):
        loaded = _load_fold_predictions(model, i)
        if loaded is None:
            continue
        probs, y, splits = loaded
        val_designs = [d for d, sp in splits.items() if sp == "val"]
        p, yy = _concat(probs, y, val_designs)
        if len(yy) == 0 or yy.sum() == 0 or yy.sum() == len(yy):
            continue
        fpr, tpr, _ = roc_curve(yy, p)
        roc_auc = auc(fpr, tpr)
        prec, rec, _ = precision_recall_curve(yy, p)
        pr_auc = auc(rec, prec)
        c = palette[i % len(palette)]
        axes[0].plot(fpr, tpr, color=c, lw=1.8, label=f"fold{i} (AUC={roc_auc:.3f})")
        axes[1].plot(rec, prec, color=c, lw=1.8, label=f"fold{i} (AUC={pr_auc:.3f})")
        any_data = True
    if not any_data:
        plt.close(fig)
        return None
    axes[0].plot([0, 1], [0, 1], color="#bbbbbb", lw=1.0, ls="--")
    axes[0].set_xlabel("false-positive rate"); axes[0].set_ylabel("true-positive rate")
    axes[0].set_title("ROC (per fold, out-of-fold)")
    axes[1].set_xlabel("recall"); axes[1].set_ylabel("precision")
    axes[1].set_title("Precision–Recall (per fold, out-of-fold)")
    for ax in axes:
        ax.set_xlim(0, 1); ax.set_ylim(0, 1.02); ax.legend(loc="lower right", fontsize=7)
    fig.suptitle(f"{model.upper()} k-fold ROC / PR ({k} folds)", y=1.02, fontsize=12, fontweight="bold")
    out = FIG_DIR / f"roc_pr_curves_kfold_{model}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ---------------------------------------------------------------- #
# 3. Score distribution                                             #
# ---------------------------------------------------------------- #
def plot_score_distribution(model: str, probs, y, design_split, split: str = "val"):
    designs = [d for d, s in design_split.items() if s == split] or list(probs.keys())
    p, yy = _concat(probs, y, designs)
    if len(p) == 0:
        return None
    fig, ax = plt.subplots(figsize=(7, 4))
    bins = np.linspace(0, 1, 41)
    ax.hist(p[yy == 0], bins=bins, color="#bbbbbb", alpha=0.85, label=f"clean (n={int((yy==0).sum())})", log=True)
    ax.hist(p[yy == 1], bins=bins, color="#cc6677", alpha=0.85, label=f"trojan (n={int((yy==1).sum())})", log=True)
    ax.axvline(0.5, color="#332288", lw=1.0, ls="--", label="threshold=0.5")
    ax.set_xlabel("predicted P(trojan)")
    ax.set_ylabel("nodes (log)")
    ax.set_title(f"{model.upper()} score distribution — {split} split")
    ax.legend(loc="upper center")
    out = FIG_DIR / f"score_distribution_{model}{CORPUS_SUFFIX}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_score_distribution_kfold(model: str, k: int):
    """Pooled out-of-fold score distribution — one figure covering every
    design in the corpus exactly once (via whichever fold held it out),
    rather than k separate per-fold distributions."""
    probs, y = _load_kfold_oof(model, k)
    if not probs:
        return None
    p, yy = _concat(probs, y, list(probs.keys()))
    fig, ax = plt.subplots(figsize=(7, 4))
    bins = np.linspace(0, 1, 41)
    ax.hist(p[yy == 0], bins=bins, color="#bbbbbb", alpha=0.85, label=f"clean (n={int((yy==0).sum())})", log=True)
    ax.hist(p[yy == 1], bins=bins, color="#cc6677", alpha=0.85, label=f"trojan (n={int((yy==1).sum())})", log=True)
    ax.axvline(0.5, color="#332288", lw=1.0, ls="--", label="threshold=0.5")
    ax.set_xlabel("predicted P(trojan)")
    ax.set_ylabel("nodes (log)")
    ax.set_title(f"{model.upper()} k-fold out-of-fold score distribution ({k} folds)")
    ax.legend(loc="upper center")
    out = FIG_DIR / f"score_distribution_kfold_{model}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ---------------------------------------------------------------- #
# 4. Reliability / calibration                                      #
# ---------------------------------------------------------------- #
def plot_calibration(model: str, probs, y, design_split, split: str = "val", n_bins: int = 12):
    designs = [d for d, s in design_split.items() if s == split] or list(probs.keys())
    p, yy = _concat(probs, y, designs)
    if len(p) == 0:
        return None
    edges = np.linspace(0, 1, n_bins + 1)
    centers, accs, sizes = [], [], []
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (p >= lo) & (p < hi) if hi < 1 else (p >= lo) & (p <= hi)
        if mask.sum() == 0:
            continue
        centers.append((lo + hi) / 2)
        accs.append(yy[mask].mean())
        sizes.append(mask.sum())
    fig, ax = plt.subplots(figsize=(5.2, 4.6))
    ax.plot([0, 1], [0, 1], color="#bbbbbb", lw=1.0, ls="--", label="perfect calibration")
    sizes = np.asarray(sizes, dtype=float)
    s_norm = 25 + 220 * (sizes / sizes.max())
    ax.scatter(centers, accs, s=s_norm, color="#117733", alpha=0.8, edgecolor="white", lw=0.8)
    ax.plot(centers, accs, color="#117733", lw=1.4)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.set_xlabel("mean predicted P(trojan) per bin")
    ax.set_ylabel("empirical fraction trojan")
    ax.set_title(f"{model.upper()} calibration — {split} split")
    ax.legend(loc="upper left")
    out = FIG_DIR / f"calibration_{model}{CORPUS_SUFFIX}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_calibration_kfold(model: str, k: int, n_bins: int = 12):
    """Per-fold reliability curves (val-only, out-of-fold) overlaid on one
    figure, color-coded by fold."""
    palette = plt.cm.tab10.colors
    fig, ax = plt.subplots(figsize=(5.2, 4.6))
    ax.plot([0, 1], [0, 1], color="#bbbbbb", lw=1.0, ls="--", label="perfect calibration")
    edges = np.linspace(0, 1, n_bins + 1)
    any_data = False
    for i in range(k):
        loaded = _load_fold_predictions(model, i)
        if loaded is None:
            continue
        probs, y, splits = loaded
        val_designs = [d for d, sp in splits.items() if sp == "val"]
        p, yy = _concat(probs, y, val_designs)
        if len(p) == 0:
            continue
        centers, accs = [], []
        for lo, hi in zip(edges[:-1], edges[1:]):
            mask = (p >= lo) & (p < hi) if hi < 1 else (p >= lo) & (p <= hi)
            if mask.sum() == 0:
                continue
            centers.append((lo + hi) / 2)
            accs.append(yy[mask].mean())
        if not centers:
            continue
        c = palette[i % len(palette)]
        ax.plot(centers, accs, color=c, lw=1.4, marker="o", ms=4, label=f"fold{i}")
        any_data = True
    if not any_data:
        plt.close(fig)
        return None
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.set_xlabel("mean predicted P(trojan) per bin")
    ax.set_ylabel("empirical fraction trojan")
    ax.set_title(f"{model.upper()} k-fold calibration ({k} folds, out-of-fold)")
    ax.legend(loc="upper left", fontsize=7)
    out = FIG_DIR / f"calibration_kfold_{model}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ---------------------------------------------------------------- #
# 5/6. Per-design F1 and AUROC bars                                 #
# ---------------------------------------------------------------- #
def _per_design_bar(model: str, metric_key: str, ylabel: str, fname: str):
    m = json.loads((GNN_DIR / f"metrics{CORPUS_SUFFIX}.json").read_text())
    per = m["per_design"]
    rows = []
    for d, info in per.items():
        v = info.get(metric_key)
        if v is None:
            continue
        rows.append((d, float(v), info.get("split", "?"), family_of(d)))
    # Sort by family then by metric desc.
    rows.sort(key=lambda r: (r[3], -r[1]))
    designs = [r[0] for r in rows]
    vals    = [r[1] for r in rows]
    colors  = [color_of(d) for d in designs]
    splits  = [r[2] for r in rows]
    hatches = {"train": "", "val": "//", "unseen": "xx"}

    fig, ax = plt.subplots(figsize=(max(8, 0.32 * len(designs)), 4.4))
    bars = ax.bar(range(len(designs)), vals, color=colors, edgecolor="black", lw=0.4)
    for bar, sp in zip(bars, splits):
        bar.set_hatch(hatches.get(sp, ""))
    ax.set_xticks(range(len(designs)))
    ax.set_xticklabels(designs, rotation=75, ha="right", fontsize=7)
    ax.set_ylabel(ylabel)
    ax.set_ylim(0, 1.02)
    ax.set_title(f"{model.upper()} per-design {ylabel} (color = trojan family, hatch = split)")

    # Compact family legend + split legend.
    fams = sorted(set(family_of(d) for d in designs))
    import matplotlib.patches as mpatches
    fam_handles = [mpatches.Patch(facecolor=FAMILY_COLORS.get(f, "#999999"),
                                  edgecolor="black", lw=0.4,
                                  label=FAMILY_LABELS.get(f, f)) for f in fams]
    split_handles = [
        mpatches.Patch(facecolor="white", edgecolor="black", hatch=h, label=s)
        for s, h in hatches.items() if s in set(splits)
    ]
    leg1 = ax.legend(handles=fam_handles, loc="upper right", fontsize=7,
                     title="family", title_fontsize=8, ncol=1)
    ax.add_artist(leg1)
    ax.legend(handles=split_handles, loc="upper left", fontsize=7,
              title="split", title_fontsize=8)
    out = FIG_DIR / fname
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_per_design_f1(model: str):
    return _per_design_bar(model, "f1", "F1", f"per_design_f1_{model}{CORPUS_SUFFIX}.png")


def plot_per_design_auroc(model: str):
    return _per_design_bar(model, "auroc", "AUROC", f"per_design_auroc_{model}{CORPUS_SUFFIX}.png")


def _load_kfold_per_design_metric(model: str, k: int, metric_key: str):
    """For each design, take its metric from the ONE fold where it was
    validation (never touched during that fold's training) — an out-of-fold
    per-design metric, one entry per design across the whole corpus."""
    rows = []  # (design, value, fold_i)
    for i in range(k):
        metrics_path = GNN_DIR / f"metrics_fold{i}.json"
        if not metrics_path.exists():
            continue
        m = json.loads(metrics_path.read_text())
        for d, info in m["per_design"].items():
            if info.get("split") != "val":
                continue
            v = info.get(metric_key)
            if v is not None:
                rows.append((d, float(v), i))
    return rows


def _per_design_bar_kfold(model: str, metric_key: str, ylabel: str, fname: str, k: int):
    rows = _load_kfold_per_design_metric(model, k, metric_key)
    if not rows:
        return None
    rows.sort(key=lambda r: (r[2], -r[1]))  # group by fold, then metric desc
    designs = [r[0] for r in rows]
    vals    = [r[1] for r in rows]
    folds   = [r[2] for r in rows]
    palette = plt.cm.tab10.colors
    colors  = [palette[f % len(palette)] for f in folds]

    fig, ax = plt.subplots(figsize=(max(8, 0.32 * len(designs)), 4.4))
    ax.bar(range(len(designs)), vals, color=colors, edgecolor="black", lw=0.4)
    ax.set_xticks(range(len(designs)))
    ax.set_xticklabels(designs, rotation=75, ha="right", fontsize=6)
    ax.set_ylabel(ylabel)
    ax.set_ylim(0, 1.02)
    ax.set_title(f"{model.upper()} k-fold per-design {ylabel} ({k} folds, out-of-fold, color = fold)")

    import matplotlib.patches as mpatches
    n_folds = max(folds) + 1
    handles = [mpatches.Patch(facecolor=palette[i % len(palette)], edgecolor="black", lw=0.4, label=f"fold{i}")
               for i in range(n_folds)]
    ax.legend(handles=handles, loc="upper right", fontsize=7, title="fold", title_fontsize=8)
    out = FIG_DIR / fname
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_per_design_f1_kfold(model: str, k: int):
    return _per_design_bar_kfold(model, "f1", "F1", f"per_design_f1_kfold_{model}.png", k)


def plot_per_design_auroc_kfold(model: str, k: int):
    return _per_design_bar_kfold(model, "auroc", "AUROC", f"per_design_auroc_kfold_{model}.png", k)


# ---------------------------------------------------------------- #
# 7. Confusion matrices by split                                    #
# ---------------------------------------------------------------- #
def plot_confusion_by_split(model: str, probs, y, design_split, thresh=0.5):
    fig, axes = plt.subplots(1, 3, figsize=(11, 3.8))
    for ax, split in zip(axes, ("train", "val", "unseen")):
        designs = [d for d, s in design_split.items() if s == split]
        p, yy = _concat(probs, y, designs)
        if len(yy) == 0:
            ax.set_axis_off()
            ax.set_title(f"{split} (empty)")
            continue
        pred = (p >= thresh).astype(int)
        cm = confusion_matrix(yy, pred, labels=[0, 1])
        im = ax.imshow(cm, cmap="Blues")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["clean", "trojan"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["clean", "trojan"])
        ax.set_xlabel("predicted"); ax.set_ylabel("true")
        ax.set_title(f"{split}  (n={len(yy)})")
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                        color="white" if cm[i, j] > cm.max() / 2 else "black",
                        fontsize=9)
    fig.suptitle(f"{model.upper()} confusion matrices by split (threshold={thresh})",
                 y=1.02, fontsize=12, fontweight="bold")
    out = FIG_DIR / f"confusion_by_split_{model}{CORPUS_SUFFIX}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_confusion_by_fold_kfold(model: str, k: int, thresh: float = 0.5):
    """One confusion matrix per fold (val-only, out-of-fold), all k panels
    in a single figure — generalizes plot_confusion_by_split's 3-panel
    train/val/unseen layout to k panels, one per fold."""
    palette = plt.cm.tab10.colors
    fig, axes = plt.subplots(1, k, figsize=(3.6 * k, 3.8))
    if k == 1:
        axes = [axes]
    for i, ax in enumerate(axes):
        c = palette[i % len(palette)]
        loaded = _load_fold_predictions(model, i)
        if loaded is None:
            ax.set_axis_off()
            ax.set_title(f"fold{i} (missing)")
            continue
        probs, y, splits = loaded
        val_designs = [d for d, sp in splits.items() if sp == "val"]
        p, yy = _concat(probs, y, val_designs)
        if len(yy) == 0:
            ax.set_axis_off()
            ax.set_title(f"fold{i} (empty)")
            continue
        pred = (p >= thresh).astype(int)
        cm = confusion_matrix(yy, pred, labels=[0, 1])
        ax.imshow(cm, cmap="Blues")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["clean", "trojan"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["clean", "trojan"])
        ax.set_xlabel("predicted"); ax.set_ylabel("true")
        ax.set_title(f"fold{i}  (n={len(yy)})", color=c, fontweight="bold")
        for r in range(2):
            for cidx in range(2):
                ax.text(cidx, r, f"{cm[r, cidx]:,}", ha="center", va="center",
                        color="white" if cm[r, cidx] > cm.max() / 2 else "black",
                        fontsize=9)
    fig.suptitle(f"{model.upper()} k-fold confusion matrices (out-of-fold, threshold={thresh})",
                 y=1.02, fontsize=12, fontweight="bold")
    out = FIG_DIR / f"confusion_by_fold_kfold_{model}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ---------------------------------------------------------------- #
# 8. Top FP/FN tables                                               #
# ---------------------------------------------------------------- #
def plot_top_errors(model: str, k: int = 10):
    m = json.loads((GNN_DIR / f"metrics{CORPUS_SUFFIX}.json").read_text())
    fp = m.get("top_false_positives", [])[:k]
    fn = m.get("top_false_negatives", [])[:k]
    if not fp and not fn:
        return None
    fig, axes = plt.subplots(1, 2, figsize=(13, 0.35 * k + 1.2))
    for ax, rows, title in zip(axes, (fp, fn), ("Top false positives", "Top false negatives")):
        ax.set_axis_off()
        ax.set_title(title, fontweight="bold", loc="left")
        if not rows:
            continue
        cell_text = [
            [r["design"], (r["node"][:60] + "…") if len(r["node"]) > 60 else r["node"],
             f"{r['score']:.3f}"]
            for r in rows
        ]
        tbl = ax.table(
            cellText=cell_text,
            colLabels=["design", "node", "P(trojan)"],
            loc="upper left",
            cellLoc="left",
            colWidths=[0.22, 0.62, 0.16],
        )
        tbl.auto_set_font_size(False)
        tbl.set_fontsize(8)
        tbl.scale(1, 1.25)
        # Header style
        for j in range(3):
            tbl[0, j].set_facecolor("#2c3e50")
            tbl[0, j].set_text_props(color="white", fontweight="bold")
        # Color by family
        for i, r in enumerate(rows, start=1):
            tbl[i, 0].set_facecolor(color_of(r["design"]))
            tbl[i, 0].set_alpha(0.4)
    fig.suptitle(f"{model.upper()} top-{k} error nodes", y=1.0, fontsize=12, fontweight="bold")
    out = FIG_DIR / f"top_errors_{model}{CORPUS_SUFFIX}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


def plot_top_errors_kfold(model: str, k_folds: int, top_k: int = 10):
    """Pooled top-FP/FN table across all folds' out-of-fold predictions —
    reuses each fold's metrics.json top-15 candidates (filtered to that
    fold's val-only designs) and re-ranks the union, so it approximates the
    true corpus-wide top errors without redoing per-node inference here.
    Rows are colored by which fold contributed them."""
    all_fp, all_fn = [], []
    for i in range(k_folds):
        metrics_path = GNN_DIR / f"metrics_fold{i}.json"
        splits_path = GNN_DIR / f"predictions_{model}_fold{i}_splits.json"
        if not metrics_path.exists() or not splits_path.exists():
            continue
        m = json.loads(metrics_path.read_text())
        splits = json.loads(splits_path.read_text())
        for r in m.get("top_false_positives", []):
            if splits.get(r["design"]) == "val":
                all_fp.append({**r, "fold": i})
        for r in m.get("top_false_negatives", []):
            if splits.get(r["design"]) == "val":
                all_fn.append({**r, "fold": i})
    all_fp.sort(key=lambda r: -r["score"])
    all_fn.sort(key=lambda r: r["score"])
    fp = all_fp[:top_k]
    fn = all_fn[:top_k]
    if not fp and not fn:
        return None

    palette = plt.cm.tab10.colors
    fig, axes = plt.subplots(1, 2, figsize=(13, 0.35 * top_k + 1.2))
    for ax, rows, title in zip(axes, (fp, fn), ("Top false positives (OOF)", "Top false negatives (OOF)")):
        ax.set_axis_off()
        ax.set_title(title, fontweight="bold", loc="left")
        if not rows:
            continue
        cell_text = [
            [r["design"], (r["node"][:55] + "…") if len(r["node"]) > 55 else r["node"],
             f"{r['score']:.3f}", f"fold{r['fold']}"]
            for r in rows
        ]
        tbl = ax.table(
            cellText=cell_text,
            colLabels=["design", "node", "P(trojan)", "fold"],
            loc="upper left",
            cellLoc="left",
            colWidths=[0.20, 0.52, 0.14, 0.14],
        )
        tbl.auto_set_font_size(False)
        tbl.set_fontsize(8)
        tbl.scale(1, 1.25)
        for j in range(4):
            tbl[0, j].set_facecolor("#2c3e50")
            tbl[0, j].set_text_props(color="white", fontweight="bold")
        for i, r in enumerate(rows, start=1):
            tbl[i, 3].set_facecolor(palette[r["fold"] % len(palette)])
            tbl[i, 3].set_alpha(0.5)
    fig.suptitle(f"{model.upper()} k-fold top-{top_k} error nodes (out-of-fold)",
                 y=1.0, fontsize=12, fontweight="bold")
    out = FIG_DIR / f"top_errors_kfold_{model}.png"
    fig.savefig(out)
    plt.close(fig)
    return out


# ---------------------------------------------------------------- #
def main():
    global CORPUS_SUFFIX
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["sage", "gcn"], default="sage")
    ap.add_argument("--thresh", type=float, default=0.5)
    ap.add_argument("--fold", default=None,
                    help="Read fold-suffixed files instead of the unsuffixed random-split "
                         "ones — 'holdout' for the 3-way train/val/test split's held-out "
                         "test figures, or a single 'fold0'..'fold{k-1}' from --split-mode kfold.")
    ap.add_argument("--kfold", type=int, default=None, metavar="K",
                    help="Generate k-fold-COMBINED figures (all K folds overlaid/pooled "
                         "into one figure each, out-of-fold) instead of the standard "
                         "per-fold set. Give the number of folds K.")
    args = ap.parse_args()
    CORPUS_SUFFIX = f"_{args.fold}" if args.fold else ""

    apply_thesis_style()
    # Yosys node names contain '$' and '\' which matplotlib otherwise parses as math.
    matplotlib.rcParams["text.parse_math"] = False
    FIG_DIR.mkdir(parents=True, exist_ok=True)

    if args.kfold:
        k = args.kfold
        written = [
            plot_training_curves_kfold(args.model, k),
            plot_roc_pr_kfold(args.model, k),
            plot_score_distribution_kfold(args.model, k),
            plot_calibration_kfold(args.model, k),
            plot_per_design_f1_kfold(args.model, k),
            plot_per_design_auroc_kfold(args.model, k),
            plot_confusion_by_fold_kfold(args.model, k, thresh=args.thresh),
            plot_top_errors_kfold(args.model, k),
        ]
        print(f"[viz_gnn] wrote {sum(1 for w in written if w)} k-fold combined figures under {FIG_DIR}")
        for w in written:
            if w:
                print(f"  - {w.name}")
        return

    probs, y, design_split = _load_predictions(args.model)

    written = []
    written.append(plot_training_curves(args.model))
    written.append(plot_roc_pr(args.model, probs, y, design_split))
    written.append(plot_score_distribution(args.model, probs, y, design_split))
    written.append(plot_calibration(args.model, probs, y, design_split))
    written.append(plot_per_design_f1(args.model))
    written.append(plot_per_design_auroc(args.model))
    written.append(plot_confusion_by_split(args.model, probs, y, design_split, thresh=args.thresh))
    written.append(plot_top_errors(args.model))

    print(f"[viz_gnn] wrote {sum(1 for w in written if w)} figures under {FIG_DIR}")
    for w in written:
        if w:
            print(f"  - {w.name}")


if __name__ == "__main__":
    main()
