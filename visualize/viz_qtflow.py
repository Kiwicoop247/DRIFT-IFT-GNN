"""
visualize/viz_qtflow.py — Phase 2 QtFlow timing-leakage figures

Per-design side-by-side DFG vs AST bars and a cross-design overview.
Reads qtflow_dfg_scores.json / qtflow_ast_scores.json from every processed
design's output directory.

Figures produced per design:
    fig_qtflow_{design}.png   — DFG and AST TLS bars side-by-side, top-K signals

Cross-design overview:
    fig_qtflow_compare.png    — category-share stacked bars + DFG-vs-AST scatter
                                + mean-TLS heatmap across all designs

Usage:
    python3 visualize/viz_qtflow.py --design AES-T2100
    python3 visualize/viz_qtflow.py --all
    python3 visualize/viz_qtflow.py --all --compare
    python3 visualize/viz_qtflow.py --all --top-k 15
"""

import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import discover_designs, get_design_config
from visualize.style import (
    apply_thesis_style,
    color_of,
    family_of,
    FAMILY_COLORS,
    FAMILY_LABELS,
)

# ── Category palette ────────────────────────────────────────────────────────────
TIMING_COLORS = {
    "TIMING_INJECTED": "#d62728",   # red      — trojan-introduced channel
    "TIMING_ELEVATED": "#ff7f0e",   # orange   — earlier cycle than golden
    "TIMING_CONTROL":  "#2166ac",   # blue     — legitimate existing ctrl flow
    "TIMING_REDUCED":  "#2ca02c",   # green    — trojan tightened the channel
    "TIMING_GHOST":    "#984ea3",   # purple   — power-side-channel artifact
    "TIMING_SAFE":     "#dddddd",   # grey     — no timing concern
    "NO_DATA":         "#eeeeee",   # off-white
}

TIMING_LABELS = {
    "TIMING_INJECTED": "Injected (trojan-only channel)",
    "TIMING_ELEVATED": "Elevated (earlier than golden)",
    "TIMING_CONTROL":  "Control (legitimate ctrl flow)",
    "TIMING_REDUCED":  "Reduced (trojan narrows channel)",
    "TIMING_GHOST":    "Ghost (power side-channel artefact)",
    "TIMING_SAFE":     "Safe (no timing leak)",
    "NO_DATA":         "No data",
}

# Order for stacked-bar plots (most alarming at bottom).
CATEGORY_ORDER = [
    "TIMING_INJECTED", "TIMING_ELEVATED", "TIMING_CONTROL",
    "TIMING_GHOST", "TIMING_REDUCED", "TIMING_SAFE",
]


# ── Helpers ─────────────────────────────────────────────────────────────────────
def _short(name: str) -> str:
    """Hierarchical → leaf signal name (mirrors fuse_labels._short_name)."""
    clean = name.replace("\\", ".")
    parts = [p for p in clean.split(".") if p and not p.startswith("$")]
    return parts[-1] if parts else name


def _load_scores(design_dir: Path, suffix: str) -> dict:
    path = design_dir / f"qtflow_{suffix}_scores.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def _family_group_order(designs: list[str]) -> list[str]:
    order = list(FAMILY_COLORS.keys()) + ["__fallback__"]
    key = {fam: i for i, fam in enumerate(order)}
    return sorted(
        designs,
        key=lambda d: (key.get(family_of(d), key["__fallback__"]), d),
    )


# ── Per-design figure ────────────────────────────────────────────────────────────
def _draw_tls_bars(ax: plt.Axes, scores: dict, top_k: int,
                   title: str, spine_color: str) -> None:
    """Draw horizontal TLS bars on *ax* for one scoring source (DFG or AST)."""
    if not scores:
        ax.text(0.5, 0.5, "No data", ha="center", va="center",
                transform=ax.transAxes, fontsize=10, color="#999")
        ax.axis("off")
        ax.set_title(title, fontsize=9, fontweight="bold")
        return

    # Sort by TLS descending, show top_k.
    ranked = sorted(scores.items(), key=lambda kv: kv[1].get("tls", 0), reverse=True)
    top = list(reversed(ranked[:top_k]))   # reverse so highest is at top

    names = [_short(n) for n, _ in top]
    tls   = [rec.get("tls", 0) for _, rec in top]
    cats  = [rec.get("category", "NO_DATA") for _, rec in top]
    bar_colors = [TIMING_COLORS.get(c, "#bbbbbb") for c in cats]

    ax.barh(range(len(top)), tls, color=bar_colors,
            edgecolor="white", linewidth=0.4, height=0.72)

    # TLS value + category label at bar tip.
    for idx, (t, cat) in enumerate(zip(tls, cats)):
        label = f"  {t:.3f}  {cat.replace('TIMING_', '')}"
        ax.text(t + 0.005, idx, label, ha="left", va="center",
                fontsize=6.5, color="#333")

    ax.axvline(0.5, color="black", lw=0.7, linestyle="--", alpha=0.4)
    ax.set_yticks(range(len(top)))
    ax.set_yticklabels(names, fontsize=7.5)
    ax.set_xlim(0, 1.35)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xticklabels(["0", "0.25", "0.5\n(neutral)", "0.75", "1.0"], fontsize=7)
    ax.set_xlabel("Timing Leakage Score (TLS)", fontsize=8)
    ax.set_title(title, fontsize=9, fontweight="bold")

    ax.spines["left"].set_color(spine_color)
    ax.spines["left"].set_linewidth(2.5)
    ax.grid(axis="x", alpha=0.2)


def render_design(design: str, output_root: Path, fig_dir: Path,
                  top_k: int = 20) -> bool:
    """Render fig_qtflow_{design}.png — DFG (left) and AST (right) bars."""
    design_dir = output_root / design
    dfg_scores = _load_scores(design_dir, "dfg")
    ast_scores = _load_scores(design_dir, "ast")

    if not dfg_scores and not ast_scores:
        print(f"  [{design}] no QtFlow output — skipping figure")
        return False

    cfg = get_design_config(design)
    fam = cfg.get("trojan_family") or cfg.get("trojan_type") or "unknown"
    fam_label = FAMILY_LABELS.get(fam, fam)
    spine_color = color_of(design)

    n_dfg_inj = sum(1 for r in dfg_scores.values()
                    if r.get("category") == "TIMING_INJECTED")
    n_ast_inj = sum(1 for r in ast_scores.values()
                    if r.get("category") == "TIMING_INJECTED")

    fig_h = max(4.0, 0.30 * top_k + 1.8)
    fig, (ax_dfg, ax_ast) = plt.subplots(1, 2, figsize=(16, fig_h))

    _draw_tls_bars(ax_dfg, dfg_scores, top_k,
                   f"DFG (gate-level)  —  {n_dfg_inj} INJECTED", spine_color)
    _draw_tls_bars(ax_ast, ast_scores, top_k,
                   f"AST (source-level)  —  {n_ast_inj} INJECTED", spine_color)

    fig.suptitle(
        f"QtFlow Timing Leakage — {design}  ·  {fam_label}\n"
        f"Top {top_k} signals by TLS; dashed line = 0.5 neutral midpoint",
        fontsize=11, fontweight="bold", y=1.01,
    )

    # Shared legend (only categories that appear in either source).
    used = set(r.get("category", "NO_DATA")
               for scores in (dfg_scores, ast_scores)
               for r in scores.values())
    handles = [
        mpatches.Patch(facecolor=TIMING_COLORS[c], edgecolor="white",
                       label=TIMING_LABELS[c])
        for c in CATEGORY_ORDER if c in used
    ]
    if handles:
        fig.legend(handles=handles, loc="lower center",
                   bbox_to_anchor=(0.5, -0.04), ncol=3,
                   fontsize=7.5, frameon=False)

    plt.tight_layout()
    fig_dir.mkdir(parents=True, exist_ok=True)
    out_path = fig_dir / f"fig_qtflow_{design}.png"
    fig.savefig(out_path, bbox_inches="tight", dpi=140)
    plt.close(fig)
    print(f"  [{design}] → {out_path.name}  "
          f"(DFG: {n_dfg_inj} inj | AST: {n_ast_inj} inj)")
    return True


# ── Cross-design figures ─────────────────────────────────────────────────────────
def _load_all(output_root: Path, designs: list[str]) -> dict:
    """Return {design: {dfg: {...}, ast: {...}}} for every design with data."""
    data: dict[str, dict] = {}
    for d in designs:
        dd = output_root / d
        dfg = _load_scores(dd, "dfg")
        ast = _load_scores(dd, "ast")
        if dfg or ast:
            data[d] = {"dfg": dfg, "ast": ast}
        else:
            print(f"  [WARN] {d}: no QtFlow scores — skipping")
    return data


def _fig_category_stacks(all_data: dict, fig_dir: Path) -> None:
    """Stacked 100% bars: QtFlow category share per design (DFG & AST side by side)."""
    designs = _family_group_order(list(all_data.keys()))
    n = len(designs)
    x = np.arange(n)
    w = 0.38

    fig, ax = plt.subplots(figsize=(max(12, n * 0.55 + 2), 6))

    for col_offset, source in [(- w / 2, "dfg"), (w / 2, "ast")]:
        bottoms = np.zeros(n)
        for cat in CATEGORY_ORDER:
            vals = np.array([
                sum(1 for r in all_data[d][source].values()
                    if r.get("category") == cat) /
                max(len(all_data[d][source]), 1) * 100
                for d in designs
            ])
            ax.bar(x + col_offset, vals, bottom=bottoms, width=w,
                   color=TIMING_COLORS[cat], edgecolor="white", linewidth=0.3,
                   label=f"{source.upper()}: {TIMING_LABELS[cat]}"
                   if col_offset < 0 else "_nolegend_")
            bottoms += vals

    ax.set_xticks(x)
    ax.set_xticklabels(designs, rotation=75, ha="right", fontsize=7)
    ax.set_ylabel("% of scored signals")
    ax.set_ylim(0, 108)
    ax.set_title("QtFlow timing-category share per design  (left = DFG, right = AST)",
                 fontsize=11, fontweight="bold")
    ax.grid(axis="y", alpha=0.2)

    handles = [mpatches.Patch(facecolor=TIMING_COLORS[c], edgecolor="white",
                               label=TIMING_LABELS[c])
               for c in CATEGORY_ORDER]
    ax.legend(handles=handles, loc="upper center",
              bbox_to_anchor=(0.5, -0.30), ncol=3, fontsize=7.5, frameon=False)

    plt.tight_layout()
    out = fig_dir / "fig_qtflow_category_stacks.png"
    fig.savefig(out, bbox_inches="tight", dpi=140)
    plt.close(fig)
    print(f"  → {out.name}")


def _fig_dfg_vs_ast_scatter(all_data: dict, fig_dir: Path) -> None:
    """Scatter: mean DFG-TLS vs mean AST-TLS per design, colored by family."""
    fig, ax = plt.subplots(figsize=(9, 7))

    for design, dd in all_data.items():
        dfg_tls = [r.get("tls", 0) for r in dd["dfg"].values()]
        ast_tls = [r.get("tls", 0) for r in dd["ast"].values()]
        if not dfg_tls or not ast_tls:
            continue
        mx = np.mean(dfg_tls)
        my = np.mean(ast_tls)
        ax.scatter([mx], [my], c=color_of(design), s=80,
                   edgecolors="white", linewidth=0.6, zorder=3)
        ax.annotate(design.replace("AES-", ""), xy=(mx, my),
                    xytext=(mx + 0.005, my + 0.004),
                    fontsize=6.5, color=color_of(design))

    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.3, zorder=1)
    ax.set_xlabel("Mean DFG Timing Leakage Score")
    ax.set_ylabel("Mean AST Timing Leakage Score")
    ax.set_title("QtFlow: mean DFG-TLS vs AST-TLS per design\n"
                 "Above diagonal = AST sees more timing risk than DFG",
                 fontsize=11, fontweight="bold")
    ax.set_xlim(0, max(0.8, ax.get_xlim()[1]))
    ax.set_ylim(0, max(0.8, ax.get_ylim()[1]))
    ax.grid(alpha=0.2)

    seen_fams = {family_of(d) for d in all_data}
    handles = [mpatches.Patch(facecolor=FAMILY_COLORS[f], edgecolor="white",
                               label=FAMILY_LABELS[f])
               for f in FAMILY_COLORS if f in seen_fams]
    ax.legend(handles=handles, loc="upper left",
              bbox_to_anchor=(1.02, 1.0), fontsize=7, frameon=False)

    plt.tight_layout()
    out = fig_dir / "fig_qtflow_dfg_ast_scatter.png"
    fig.savefig(out, bbox_inches="tight", dpi=140)
    plt.close(fig)
    print(f"  → {out.name}")


def _fig_injected_bar(all_data: dict, fig_dir: Path) -> None:
    """Grouped bar: TIMING_INJECTED count per design, DFG vs AST."""
    designs = _family_group_order(list(all_data.keys()))
    n = len(designs)
    x = np.arange(n)
    w = 0.35

    dfg_counts = [
        sum(1 for r in all_data[d]["dfg"].values()
            if r.get("category") == "TIMING_INJECTED")
        for d in designs
    ]
    ast_counts = [
        sum(1 for r in all_data[d]["ast"].values()
            if r.get("category") == "TIMING_INJECTED")
        for d in designs
    ]

    fig, ax = plt.subplots(figsize=(max(10, n * 0.55 + 2), 5))
    bars_dfg = ax.bar(x - w / 2, dfg_counts, width=w,
                      color="#2166ac", alpha=0.85,
                      edgecolor="white", linewidth=0.4, label="DFG")
    bars_ast = ax.bar(x + w / 2, ast_counts, width=w,
                      color="#d62728", alpha=0.85,
                      edgecolor="white", linewidth=0.4, label="AST")

    vmax = max(max(dfg_counts, default=0), max(ast_counts, default=0), 1)
    for bar, v in zip(list(bars_dfg) + list(bars_ast),
                      dfg_counts + ast_counts):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + vmax * 0.02, str(v),
                    ha="center", va="bottom", fontsize=7)

    ax.set_xticks(x)
    ax.set_xticklabels(designs, rotation=75, ha="right", fontsize=7)
    ax.set_ylabel("TIMING_INJECTED signal count")
    ax.set_title("Trojan-injected timing channels: DFG vs AST count per design\n"
                 "Blue = gate-level (DFG), Red = source-level (AST)",
                 fontsize=11, fontweight="bold")
    ax.set_ylim(0, vmax * 1.18)
    ax.legend(fontsize=9, frameon=False)
    ax.grid(axis="y", alpha=0.2)

    # Color spine by family.
    for tick, design in zip(ax.get_xticklabels(), designs):
        tick.set_color(color_of(design))

    plt.tight_layout()
    out = fig_dir / "fig_qtflow_injected_bar.png"
    fig.savefig(out, bbox_inches="tight", dpi=140)
    plt.close(fig)
    print(f"  → {out.name}")


def _fig_tls_heatmap(all_data: dict, fig_dir: Path) -> None:
    """Heatmap: mean TLS per design × (DFG / AST) × category bucket."""
    designs = _family_group_order(list(all_data.keys()))
    # Columns: DFG mean-TLS, AST mean-TLS, DFG INJECTED%, AST INJECTED%
    col_labels = ["DFG\nmean TLS", "AST\nmean TLS",
                  "DFG\nINJECTED%", "AST\nINJECTED%"]
    nc = len(col_labels)
    nd = len(designs)

    matrix = np.zeros((nd, nc))
    for di, d in enumerate(designs):
        dfg = all_data[d]["dfg"]
        ast = all_data[d]["ast"]
        if dfg:
            matrix[di, 0] = np.mean([r.get("tls", 0) for r in dfg.values()])
            matrix[di, 2] = (sum(1 for r in dfg.values()
                                  if r.get("category") == "TIMING_INJECTED")
                              / len(dfg) * 100)
        if ast:
            matrix[di, 1] = np.mean([r.get("tls", 0) for r in ast.values()])
            matrix[di, 3] = (sum(1 for r in ast.values()
                                  if r.get("category") == "TIMING_INJECTED")
                              / len(ast) * 100)

    fig, ax = plt.subplots(figsize=(8, max(4, nd * 0.38 + 1.2)))
    im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto", vmin=0, vmax=1)
    plt.colorbar(im, ax=ax, fraction=0.035, pad=0.02,
                 label="Score / fraction")

    ax.set_xticks(range(nc))
    ax.set_xticklabels(col_labels, fontsize=8)
    ax.set_yticks(range(nd))
    ax.set_yticklabels(designs, fontsize=7)
    ax.set_title("QtFlow mean TLS and INJECTED% per design",
                 fontsize=11, fontweight="bold")

    for tick, design in zip(ax.get_yticklabels(), designs):
        tick.set_color(color_of(design))

    vmax = matrix.max() if matrix.max() > 0 else 1
    for di in range(nd):
        for ci in range(nc):
            v = matrix[di, ci]
            fmt = f"{v:.2f}" if ci < 2 else f"{v:.0f}%"
            ax.text(ci, di, fmt, ha="center", va="center",
                    fontsize=6, color="white" if v > vmax * 0.6 else "black")

    plt.tight_layout()
    out = fig_dir / "fig_qtflow_heatmap.png"
    fig.savefig(out, bbox_inches="tight", dpi=140)
    plt.close(fig)
    print(f"  → {out.name}")


def render_compare(output_root: Path, fig_dir: Path) -> None:
    """Generate all cross-design QtFlow comparison figures."""
    designs = _family_group_order(list(discover_designs()))
    all_data = _load_all(output_root, designs)
    if not all_data:
        print("No designs with QtFlow output found — run qtflow_dfg.py first.")
        return

    print(f"\nCross-design QtFlow comparison ({len(all_data)} designs):")
    _fig_category_stacks(all_data, fig_dir)
    _fig_dfg_vs_ast_scatter(all_data, fig_dir)
    _fig_injected_bar(all_data, fig_dir)
    _fig_tls_heatmap(all_data, fig_dir)

    # ── Combined sheet ────────────────────────────────────────────────────────
    # Compact 2×2 grid: stacks (top-left), scatter (top-right),
    # injected-bar (bottom-left), heatmap (bottom-right).
    n = len(all_data)
    fig = plt.figure(figsize=(18, 14))
    gs  = fig.add_gridspec(2, 2, hspace=0.55, wspace=0.35,
                           top=0.92, bottom=0.07, left=0.06, right=0.94)
    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = fig.add_subplot(gs[0, 1])
    ax3 = fig.add_subplot(gs[1, 0])
    ax4 = fig.add_subplot(gs[1, 1])

    designs_ord = _family_group_order(list(all_data.keys()))
    _inline_category_stacks(all_data, designs_ord, ax1)
    _inline_dfg_ast_scatter(all_data, ax2)
    _inline_injected_bar(all_data, designs_ord, ax3)
    _inline_tls_heatmap(all_data, designs_ord, ax4)

    fig.suptitle(
        "QtFlow Phase 2 — Timing Leakage Analysis  ·  Cross-Design Overview\n"
        "DFG (gate-level) vs AST (source-level) timing-sensitivity scoring",
        fontsize=13, fontweight="bold", y=0.97,
    )
    out = fig_dir / "fig_qtflow_compare.png"
    fig.savefig(out, dpi=110, bbox_inches="tight")
    plt.close(fig)
    print(f"  → {out.name}  (combined sheet)")


# ── Inline versions for the combined sheet (axes-only, no save) ────────────────
def _inline_category_stacks(all_data: dict, designs: list[str], ax: plt.Axes) -> None:
    n = len(designs)
    x = np.arange(n)
    w = 0.38
    for col_offset, source in [(-w / 2, "dfg"), (w / 2, "ast")]:
        bottoms = np.zeros(n)
        for cat in CATEGORY_ORDER:
            vals = np.array([
                sum(1 for r in all_data[d][source].values()
                    if r.get("category") == cat) /
                max(len(all_data[d][source]), 1) * 100
                for d in designs
            ])
            ax.bar(x + col_offset, vals, bottom=bottoms, width=w,
                   color=TIMING_COLORS[cat], edgecolor="white", linewidth=0.3)
            bottoms += vals
    ax.set_xticks(x)
    ax.set_xticklabels(designs, rotation=75, ha="right", fontsize=6)
    ax.set_ylabel("% of scored signals", fontsize=8)
    ax.set_ylim(0, 108)
    ax.set_title("Category share (left=DFG, right=AST)", fontsize=9, fontweight="bold")
    ax.grid(axis="y", alpha=0.2)
    handles = [mpatches.Patch(facecolor=TIMING_COLORS[c], edgecolor="white",
                               label=c.replace("TIMING_", "").title())
               for c in CATEGORY_ORDER]
    ax.legend(handles=handles, loc="upper right", fontsize=6, frameon=True,
              framealpha=0.85, ncol=2)


def _inline_dfg_ast_scatter(all_data: dict, ax: plt.Axes) -> None:
    for design, dd in all_data.items():
        dfg_tls = [r.get("tls", 0) for r in dd["dfg"].values()]
        ast_tls = [r.get("tls", 0) for r in dd["ast"].values()]
        if not dfg_tls or not ast_tls:
            continue
        mx, my = np.mean(dfg_tls), np.mean(ast_tls)
        ax.scatter([mx], [my], c=color_of(design), s=70,
                   edgecolors="white", linewidth=0.6, zorder=3)
        ax.annotate(design.replace("AES-", ""), xy=(mx, my),
                    xytext=(mx + 0.004, my + 0.003),
                    fontsize=6, color=color_of(design))
    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.3, zorder=1)
    ax.set_xlabel("Mean DFG TLS", fontsize=8)
    ax.set_ylabel("Mean AST TLS", fontsize=8)
    ax.set_title("Mean DFG vs AST TLS per design", fontsize=9, fontweight="bold")
    ax.grid(alpha=0.2)


def _inline_injected_bar(all_data: dict, designs: list[str], ax: plt.Axes) -> None:
    n = len(designs)
    x = np.arange(n)
    w = 0.35
    dfg_c = [sum(1 for r in all_data[d]["dfg"].values()
                 if r.get("category") == "TIMING_INJECTED") for d in designs]
    ast_c = [sum(1 for r in all_data[d]["ast"].values()
                 if r.get("category") == "TIMING_INJECTED") for d in designs]
    ax.bar(x - w / 2, dfg_c, width=w, color="#2166ac", alpha=0.85,
           edgecolor="white", linewidth=0.3, label="DFG")
    ax.bar(x + w / 2, ast_c, width=w, color="#d62728", alpha=0.85,
           edgecolor="white", linewidth=0.3, label="AST")
    ax.set_xticks(x)
    ax.set_xticklabels(designs, rotation=75, ha="right", fontsize=6)
    ax.set_ylabel("TIMING_INJECTED count", fontsize=8)
    ax.set_title("Injected timing channels per design", fontsize=9, fontweight="bold")
    vmax = max(max(dfg_c, default=0), max(ast_c, default=0), 1)
    ax.set_ylim(0, vmax * 1.2)
    ax.legend(fontsize=8, frameon=False)
    ax.grid(axis="y", alpha=0.2)


def _inline_tls_heatmap(all_data: dict, designs: list[str], ax: plt.Axes) -> None:
    col_labels = ["DFG\nmean TLS", "AST\nmean TLS",
                  "DFG\nINJECTED%", "AST\nINJECTED%"]
    nc, nd = len(col_labels), len(designs)
    matrix = np.zeros((nd, nc))
    for di, d in enumerate(designs):
        dfg = all_data[d]["dfg"]
        ast = all_data[d]["ast"]
        if dfg:
            matrix[di, 0] = np.mean([r.get("tls", 0) for r in dfg.values()])
            matrix[di, 2] = (sum(1 for r in dfg.values()
                                  if r.get("category") == "TIMING_INJECTED")
                              / len(dfg) * 100)
        if ast:
            matrix[di, 1] = np.mean([r.get("tls", 0) for r in ast.values()])
            matrix[di, 3] = (sum(1 for r in ast.values()
                                  if r.get("category") == "TIMING_INJECTED")
                              / len(ast) * 100)
    im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto", vmin=0)
    plt.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    ax.set_xticks(range(nc))
    ax.set_xticklabels(col_labels, fontsize=7)
    ax.set_yticks(range(nd))
    ax.set_yticklabels(designs, fontsize=6)
    ax.set_title("TLS heatmap (DFG / AST)", fontsize=9, fontweight="bold")
    vmax = matrix.max() if matrix.max() > 0 else 1
    for di in range(nd):
        for ci in range(nc):
            v = matrix[di, ci]
            fmt = f"{v:.2f}" if ci < 2 else f"{v:.0f}%"
            ax.text(ci, di, fmt, ha="center", va="center",
                    fontsize=5.5, color="white" if v > vmax * 0.6 else "black")
    for tick, design in zip(ax.get_yticklabels(), designs):
        tick.set_color(color_of(design))


# ── Main ────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="QtFlow Phase 2 visualization — TLS bars and cross-design comparison"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--design", metavar="NAME",
                       help="Render per-design bars for one design")
    group.add_argument("--all", action="store_true",
                       help="Render per-design bars for all designs")
    parser.add_argument("--compare", action="store_true",
                        help="Also render cross-design comparison figures")
    parser.add_argument("--top-k", type=int, default=20,
                        help="Number of signals to show per design (default 20)")
    parser.add_argument("--output-dir", default=None,
                        help="Figures directory (default outputs/figures/)")
    args = parser.parse_args()

    apply_thesis_style()

    pipeline_root = Path(__file__).parent.parent
    output_root   = pipeline_root / "outputs"
    fig_dir       = (Path(args.output_dir) if args.output_dir
                     else output_root / "figures")

    if args.design:
        render_design(args.design, output_root, fig_dir, top_k=args.top_k)
    elif args.all:
        designs = discover_designs()
        n_ok = n_skip = 0
        for d in designs:
            ok = render_design(d, output_root, fig_dir, top_k=args.top_k)
            n_ok += int(ok)
            n_skip += int(not ok)
        print(f"\nQtFlow bars: {n_ok} rendered, {n_skip} skipped")
    else:
        # Default: just do compare if no design specified.
        args.compare = True

    if args.compare or (not args.design and not args.all):
        render_compare(output_root, fig_dir)


if __name__ == "__main__":
    main()
