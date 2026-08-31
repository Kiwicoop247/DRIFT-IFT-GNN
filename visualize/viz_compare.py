"""
visualize/viz_compare.py — Cross-design comparison figures (thesis figures)

Reads combined_labels.json from every processed design and produces thesis-
ready comparison figures. Colors resolve through visualize/style.py so the
palette stays consistent across all figure scripts.

Figures produced:
    fig_dfg_ast_scatter.png     — DFG vs AST scatter, standalone (fixed size —
                                  doesn't get harder to read as corpus grows)
    fig_detection_rate.png      — detection rate bars, standalone (width scales
                                  with design count)
    fig_ast_count_heatmap.png   — AST-only signal count bars + delta heatmap
    fig_summary_table.png       — per-design detectability table
    fig_full_comparison.png     — all five panels in one sheet (scales with n)

Run after stage4_fusion/fuse_labels.py has completed for all designs:
    python3 visualize/viz_compare.py
    python3 visualize/viz_compare.py --output-dir outputs/figures/
"""

import sys
import json
import argparse
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import get_design_config, discover_designs
from visualize.style import (
    FAMILY_COLORS,
    FAMILY_LABELS,
    CATEGORY_COLORS,
    TABLE_HEADER_BG,
    TABLE_HEADER_FG,
    TABLE_T2100_BG,
    TABLE_DETECT_PASS,
    TABLE_DETECT_FAIL,
    color_of,
    family_of,
    apply_thesis_style,
    family_legend_handles,
)

# Human-readable short label for the summary table's trojan-type column.
TROJAN_TYPE_SHORT = {
    "power_side_channel":          "power\nside-channel",
    "side_channel":                "side-channel",
    "combinational_trigger":       "combinational\ntrigger",
    "sequential_counter_trigger":  "sequential\ncounter",
    "data_exfil":                  "data\nexfiltration",
    "power_drain":                 "power\ndrain",
    "dos":                         "denial of\nservice",
    "leak_info":                   "leakage\n(inline)",
    "corruption":                  "data\ncorruption",
    "spoofing":                    "spoofing",
    "other":                       "other",
    "unknown":                     "unknown",
}


def _family_group_order(designs: list[str]) -> list[str]:
    """Sort designs so same-family entries are adjacent.

    Stable: within a family, keep the original lexical order.
    """
    order = list(FAMILY_COLORS.keys()) + ["__fallback__"]
    key = {fam: i for i, fam in enumerate(order)}
    return sorted(
        designs,
        key=lambda d: (key.get(family_of(d), key["__fallback__"]), d),
    )


def load_all_designs(output_root: Path) -> dict:
    """Load combined_labels.json for every design in stage0_designs/ that has one."""
    designs = sorted(discover_designs())
    data = {}
    for design in designs:
        path = output_root / design / "combined_labels.json"
        if path.exists():
            with open(path) as f:
                data[design] = json.load(f)
        else:
            print(f"  [WARN] {design}: combined_labels.json not found — skipping")
    return data


# ── Figure 1 ───────────────────────────────────────────────────────────────────
def figure1_detection_rate(all_data: dict, ax: plt.Axes) -> None:
    """Stacked bar of fusion categories per design (100% stacked)."""
    cats   = ["AGREE_HIGH", "AST_ONLY_HIGH", "DFG_ONLY_HIGH", "AGREE_LOW"]
    labels = [
        "Both detect (AGREE_HIGH)",
        "AST-only (AST_ONLY_HIGH)",
        "DFG-only (DFG_ONLY_HIGH)",
        "Both miss (AGREE_LOW)",
    ]

    designs = _family_group_order(list(all_data.keys()))
    n = len(designs)
    x = np.arange(n)

    matrix = np.zeros((len(cats), n))
    for di, d in enumerate(designs):
        signals = all_data[d]
        total = max(len(signals), 1)
        for ci, cat in enumerate(cats):
            count = sum(1 for s in signals.values() if s.get("category") == cat)
            matrix[ci, di] = count / total * 100

    bottoms = np.zeros(n)
    for ci, cat in enumerate(cats):
        ax.bar(
            x, matrix[ci], bottom=bottoms, width=0.78,
            color=CATEGORY_COLORS[cat], edgecolor="white", linewidth=0.4,
            label=labels[ci],
        )
        bottoms += matrix[ci]

    ax.set_xticks(x)
    ax.set_xticklabels(designs, rotation=75, ha="right", fontsize=7)
    ax.set_ylabel("% of signals")
    ax.set_title("Fusion category share per design "
                 "(sorted by trojan family)")
    ax.set_ylim(0, 102)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.32),
              ncol=2, fontsize=8, frameon=False)
    ax.grid(axis="y", alpha=0.2)


# ── Figure 2 ───────────────────────────────────────────────────────────────────
def figure2_dfg_ast_scatter(all_data: dict, ax: plt.Axes) -> None:
    """Scatter: DFG vs AST score; colored by trojan family."""
    seen_families: set[str] = set()
    for design, signals in all_data.items():
        fam = family_of(design)
        color = color_of(design)
        xs = [s["dfg_score"] for s in signals.values() if "dfg_score" in s]
        ys = [s["ast_score"] for s in signals.values() if "ast_score" in s]
        # T2100 on top so its annotations sit above the cloud
        z = 3 if fam == "power_side_channel" else 2
        ax.scatter(xs, ys, c=color, s=18, alpha=0.55, zorder=z,
                   edgecolors="none")
        seen_families.add(fam)

    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.35, zorder=1)
    ax.axhline(0.08, color="grey", lw=0.7, linestyle=":", alpha=0.5)
    ax.axvline(0.08, color="grey", lw=0.7, linestyle=":", alpha=0.5)

    # Annotate the thesis' T2100 signals with non-overlapping offsets.
    t2100 = all_data.get("AES-T2100", {})
    annotations = [
        ("SECRETKey", ( 0.18,  0.12)),
        ("COUNTER",   (-0.20,  0.16)),
        ("LEAKBit",   ( 0.14, -0.12)),
        ("Tj_Trig",   (-0.20, -0.12)),
    ]
    for sig, (dx, dy) in annotations:
        if sig not in t2100:
            continue
        r = t2100[sig]
        ax.annotate(
            sig,
            xy=(r["dfg_score"], r["ast_score"]),
            xytext=(r["dfg_score"] + dx, r["ast_score"] + dy),
            fontsize=7, fontweight="bold",
            color=FAMILY_COLORS["power_side_channel"],
            arrowprops=dict(arrowstyle="->", lw=0.7,
                            color=FAMILY_COLORS["power_side_channel"]),
            bbox=dict(boxstyle="round,pad=0.2",
                      fc="white", ec="none", alpha=0.85),
        )

    # Legend: one entry per trojan family that actually has points here.
    handles = [
        mpatches.Patch(facecolor=FAMILY_COLORS[f], edgecolor="white",
                       label=FAMILY_LABELS[f])
        for f in FAMILY_COLORS
        if f in seen_families
    ]
    handles.append(plt.Line2D([0], [0], color="black", lw=1,
                              linestyle="--", label="perfect agreement"))
    ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(1.02, 1.0),
              fontsize=7, frameon=False, borderaxespad=0)

    ax.set_xlabel("DFG taint score (gate-level)")
    ax.set_ylabel("AST taint score (source-level)")
    ax.set_title("DFG vs AST scores — all designs\n"
                 "Above diagonal: AST catches what synthesis removes")
    ax.set_xlim(-0.02, 1.05)
    ax.set_ylim(-0.02, 1.05)
    ax.grid(alpha=0.2)


# ── Figure 3 ───────────────────────────────────────────────────────────────────
def figure3_ast_only_count(all_data: dict, ax: plt.Axes,
                           show_legend: bool = True) -> None:
    """Bar: number of AST_ONLY_HIGH signals per design, colored by family."""
    designs = _family_group_order(list(all_data.keys()))
    vals = [
        sum(1 for s in all_data[d].values() if s.get("category") == "AST_ONLY_HIGH")
        for d in designs
    ]
    colors = [color_of(d) for d in designs]
    x = np.arange(len(designs))
    bars = ax.bar(x, vals, color=colors, alpha=0.9,
                  edgecolor="white", linewidth=0.5, width=0.75)
    vmax = max(vals) if vals else 1
    for bar, v in zip(bars, vals):
        if v > 0:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + vmax * 0.02, str(v),
                    ha="center", va="bottom", fontsize=7)

    ax.set_xticks(x)
    ax.set_xticklabels(designs, rotation=75, ha="right", fontsize=7)
    ax.set_ylabel("AST_ONLY_HIGH signal count")
    ax.set_title("Signals DFG misses but AST catches\n"
                 "(power-side-channel family expected to dominate)")
    ax.set_ylim(0, max(vmax * 1.15, 1))
    ax.grid(axis="y", alpha=0.2)

    # Family legend outside axes (right side) so it does not cover bars.
    # Suppress in the combined figure where the scatter panel already shows it.
    if show_legend:
        seen = {family_of(d) for d in designs}
        handles = [mpatches.Patch(facecolor=FAMILY_COLORS[f], edgecolor="white",
                                  label=FAMILY_LABELS[f])
                   for f in FAMILY_COLORS if f in seen]
        ax.legend(handles=handles, loc="upper left", bbox_to_anchor=(1.02, 1.0),
                  fontsize=7, frameon=False, borderaxespad=0)


# ── Figure 4 ───────────────────────────────────────────────────────────────────
def figure4_delta_heatmap(all_data: dict, ax: plt.Axes) -> None:
    """Heatmap: mean |delta_score| per design × signal role."""
    roles        = ["source", "sink", "trojan_intermediate",
                    "key_intermediate", "internal"]
    role_labels  = ["source", "sink", "trojan", "key sched", "internal"]
    designs      = _family_group_order(list(all_data.keys()))

    matrix = np.zeros((len(designs), len(roles)))
    for di, design in enumerate(designs):
        role_deltas: dict[str, list[float]] = defaultdict(list)
        for sig, sc in all_data[design].items():
            role = sc.get("dfg_role", sc.get("ast_role", "internal"))
            delta = abs(sc.get("delta_score", 0.0))
            role_deltas[role].append(delta)
        for ri, role in enumerate(roles):
            vals = role_deltas.get(role, [0])
            matrix[di, ri] = sum(vals) / len(vals) if vals else 0.0

    vmax = max(matrix.max(), 0.01)
    im = ax.imshow(matrix, cmap="YlOrRd", aspect="auto", vmin=0, vmax=vmax)
    cbar = plt.colorbar(im, ax=ax, label="|Δ score| (full − golden)",
                        fraction=0.035, pad=0.02)
    cbar.ax.tick_params(labelsize=7)

    ax.set_xticks(range(len(roles)))
    ax.set_xticklabels(role_labels, fontsize=8)
    ax.set_yticks(range(len(designs)))
    ax.set_yticklabels(designs, fontsize=7)
    ax.set_title("Per-role delta score heatmap "
                 "(|full IFT − golden baseline|)")

    # Color y-tick labels by trojan family so the viewer sees the grouping.
    for tick, design in zip(ax.get_yticklabels(), designs):
        tick.set_color(color_of(design))

    for di in range(len(designs)):
        for ri in range(len(roles)):
            v = matrix[di, ri]
            text_color = "white" if v > vmax * 0.55 else "black"
            ax.text(ri, di, f"{v:.2f}", ha="center", va="center",
                    fontsize=6, color=text_color)


# ── Figure 5 ───────────────────────────────────────────────────────────────────
def figure5_summary_table(all_data: dict, ax: plt.Axes) -> None:
    """Per-design detectability summary table."""
    ax.axis("off")
    designs = sorted(all_data.keys())

    headers = ["Design", "Trojan type", "DFG\ndetects?", "AST\ndetects?",
               "Top DFG signal (score)", "Top AST signal (score)"]

    rows = []
    for design in designs:
        cfg          = get_design_config(design)
        trojan_type  = cfg.get("trojan_type") or cfg.get("trojan_family") or "unknown"
        if trojan_type == "unknown":
            trojan_type = cfg.get("trojan_effect") or "unknown"
        signals      = all_data[design]

        dfg_candidates = [(s, d["dfg_score"]) for s, d in signals.items()
                          if d["dfg_score"] > 0.05 and d.get("is_on_trojan_path", 0)]
        dfg_candidates.sort(key=lambda x: x[1], reverse=True)
        top_dfg = (f"{dfg_candidates[0][0][:18]} ({dfg_candidates[0][1]:.3f})"
                   if dfg_candidates else "—")

        ast_candidates = [(s, d["ast_score"]) for s, d in signals.items()
                          if d["ast_score"] > 0.05]
        ast_candidates.sort(key=lambda x: x[1], reverse=True)
        top_ast = (f"{ast_candidates[0][0][:18]} ({ast_candidates[0][1]:.3f})"
                   if ast_candidates else "—")

        dfg_detects = any(d["dfg_score"] > 0.05 and d.get("is_on_trojan_path", 0)
                          for d in signals.values())
        ast_detects = any(d["ast_score"] > 0.08 and
                          d.get("category") == "AST_ONLY_HIGH"
                          for d in signals.values())

        rows.append([
            design,
            TROJAN_TYPE_SHORT.get(trojan_type, trojan_type),
            "✓" if dfg_detects else "✗",
            "✓" if ast_detects else "✗",
            top_dfg,
            top_ast,
        ])

    col_widths = [0.12, 0.16, 0.10, 0.10, 0.26, 0.26]
    table = ax.table(
        cellText=rows,
        colLabels=headers,
        cellLoc="center",
        loc="upper center",
        colWidths=col_widths,
    )
    table.auto_set_font_size(False)
    table.set_fontsize(7)
    table.scale(1.0, 1.5)

    for j in range(len(headers)):
        table[0, j].set_facecolor(TABLE_HEADER_BG)
        table[0, j].set_text_props(color=TABLE_HEADER_FG, fontweight="bold")

    # Highlight T2100 by name, not by index — prevents the long-standing bug
    # where sorted(designs) put AES-T100 at row 1 instead of T2100.
    if "AES-T2100" in designs:
        t2100_row = designs.index("AES-T2100") + 1   # +1 for header row
        for j in range(len(headers)):
            table[t2100_row, j].set_facecolor(TABLE_T2100_BG)

    for i in range(1, len(rows) + 1):
        for j in (2, 3):
            val = table[i, j].get_text().get_text()
            if val == "✓":
                table[i, j].set_facecolor(TABLE_DETECT_PASS)
            elif val == "✗":
                table[i, j].set_facecolor(TABLE_DETECT_FAIL)

    # Title via ax.text() (the axis has axis("off"); set_title with pad bleeds
    # into the table body). Placed just above the upper-anchored table.
    ax.text(
        0.5, 1.04,
        "Trojan detectability summary  —  per-design DFG vs AST results",
        ha="center", va="bottom", transform=ax.transAxes,
        fontsize=11, fontweight="bold",
    )


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Generate cross-design comparison figures (thesis figures)"
    )
    parser.add_argument("--output-dir", default=None,
                        help="Directory to save figures (default: outputs/figures/)")
    args = parser.parse_args()

    apply_thesis_style()

    pipeline_root = Path(__file__).parent.parent
    output_root   = pipeline_root / "outputs"
    fig_dir       = Path(args.output_dir) if args.output_dir else output_root / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    print("Loading design data ...")
    all_data = load_all_designs(output_root)
    if not all_data:
        print("No designs with combined_labels.json found. Run fuse_labels.py first.")
        sys.exit(1)
    n = len(all_data)
    print(f"  Loaded {n} designs")

    # ── A1: DFG vs AST scatter — standalone, kept separate from the bar chart
    # (unlike the per-design bars below, the scatter doesn't get harder to
    # read as design count grows — it's just a point cloud — so it's the one
    # figure that stays a fixed, generous size regardless of corpus size).
    fig, ax = plt.subplots(figsize=(11, 9.5))
    fig.suptitle("DFG vs AST detection — all designs",
                 fontsize=13, fontweight="bold", y=1.00)
    figure2_dfg_ast_scatter(all_data, ax)
    out_scatter = fig_dir / "fig_dfg_ast_scatter.png"
    fig.savefig(out_scatter, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved → {out_scatter}")

    # ── A2: Detection rate bars — standalone, width scales with design count
    # so per-design x-tick labels stay legible across 36 -> 226+ designs.
    fig, ax = plt.subplots(figsize=(max(17, n * 0.16), 6.5))
    fig.suptitle("IFT Pipeline — Fusion Category Share per Design",
                 fontsize=13, fontweight="bold", y=1.02)
    figure1_detection_rate(all_data, ax)
    out_a = fig_dir / "fig_detection_rate.png"
    fig.savefig(out_a, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved → {out_a}")

    # ── B: AST-only count + heatmap ────────────────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(max(17, n * 0.16), max(7, n * 0.22)),
                             gridspec_kw={"width_ratios": [1.1, 1.0]})
    figure3_ast_only_count(all_data, axes[0])
    figure4_delta_heatmap(all_data, axes[1])
    plt.tight_layout()
    out_b = fig_dir / "fig_ast_count_heatmap.png"
    fig.savefig(out_b, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved → {out_b}")

    # ── C: Summary table ───────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(14, 0.32 * len(all_data) + 1.5))
    figure5_summary_table(all_data, ax)
    out_c = fig_dir / "fig_summary_table.png"
    fig.savefig(out_c, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved → {out_c}")

    # ── D: Full comparison (all 5 panels) ─────────────────────────────────────
    # Scales with n so it stays readable as stage0_designs/ grows — the
    # summary table (ax5) needs the most extra vertical room per design.
    fig_height = max(20, 6 + n * 0.35)
    fig = plt.figure(figsize=(16, fig_height))
    gs  = fig.add_gridspec(
        3, 2,
        hspace=0.85, wspace=0.32,
        height_ratios=[1.0, 1.0, 2.0 + n * 0.03],
        top=0.93, bottom=0.03, left=0.06, right=0.94,
    )

    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = fig.add_subplot(gs[0, 1])
    ax3 = fig.add_subplot(gs[1, 0])
    ax4 = fig.add_subplot(gs[1, 1])
    ax5 = fig.add_subplot(gs[2, :])

    figure1_detection_rate(all_data, ax1)
    figure2_dfg_ast_scatter(all_data, ax2)
    figure3_ast_only_count(all_data, ax3, show_legend=False)
    figure4_delta_heatmap(all_data, ax4)
    figure5_summary_table(all_data, ax5)

    fig.suptitle(
        "Multi-View IFT Analysis — Trust-Hub Benchmark Suite\n"
        "DFG (gate-level) vs AST (source-level) Trojan Detection",
        fontsize=14, fontweight="bold", y=0.975,
    )
    out_d = fig_dir / "fig_full_comparison.png"
    fig.savefig(out_d, dpi=110)
    plt.close(fig)
    print(f"  Saved → {out_d}")

    print(f"\nAll figures saved to: {fig_dir}/")


if __name__ == "__main__":
    main()
