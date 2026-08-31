"""
visualize/viz_glra_bars.py — Phase 1 "aha" figure: GLRA risk bars

Per-design horizontal bar chart showing the top-K signals by GLRA risk
deviation from the golden baseline. Each bar is drawn from the neutral
risk_score = 0.5 midline:
    risk > 0.5  → bar extends RIGHT, filled red     ("leakier than golden")
    risk < 0.5  → bar extends LEFT, filled green    ("tighter than golden")
    risk = 0.5  → no bar                            (neutral / no GLRA data)

Designs with empty GLRA output (no auto-detected sources — PIC/RS232/
wb_conmax) are skipped gracefully, not rendered.

Usage:
    python3 visualize/viz_glra_bars.py --design AES-T2100
    python3 visualize/viz_glra_bars.py --all
    python3 visualize/viz_glra_bars.py --all --top-k 15
"""

import sys
import json
import argparse
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import discover_designs
from visualize.style import apply_thesis_style, color_of, FAMILY_LABELS

CATEGORY_BAR_COLORS = {
    "INJECTED":    "#d62728",   # strong red    — trojan-only signal
    "ELEVATED":    "#ff7f0e",   # orange        — cheaper than golden
    "TARGET_ONLY": "#ff9896",   # light red     — target-only, non-trojan
    "NO_CHANGE":   "#bbbbbb",   # grey          — unperturbed
    "REDUCED":     "#2ca02c",   # green         — harder than golden (rare)
    "GOLDEN_ONLY": "#98df8a",   # light green   — trojan removed a path
    "NO_DATA":     "#eeeeee",   # near-white    — no GLRA coverage
}


def _load_glra_scores(output_dir: Path) -> dict:
    path = output_dir / "glra_dfg_scores.json"
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def _short(name: str) -> str:
    """Mirror fuse_labels._short_name — hierarchical → leaf signal name."""
    clean = name.replace("\\", ".")
    parts = [p for p in clean.split(".") if p and not p.startswith("$")]
    return parts[-1] if parts else name


def render_design(design: str, output_root: Path, fig_dir: Path,
                  top_k: int = 20) -> bool:
    """Render fig_glra_<design>.png. Returns True on render, False if empty."""
    design_dir = output_root / design
    scores = _load_glra_scores(design_dir)

    # Keep only signals with actionable GLRA output (drop neutral NO_CHANGE and
    # everything with risk == 0.5 — no information for the reader).
    interesting = [
        (name, rec) for name, rec in scores.items()
        if rec.get("category") not in ("NO_CHANGE",)
        and rec.get("risk_score", 0.5) != 0.5
    ]
    if not interesting:
        print(f"  [{design}] no non-neutral GLRA signals — skipping figure")
        return False

    # Sort by absolute deviation from the 0.5 midline, most extreme first.
    interesting.sort(
        key=lambda kv: abs(kv[1].get("risk_score", 0.5) - 0.5),
        reverse=True,
    )
    top = interesting[:top_k]

    # Plot in reverse order so the strongest bar sits at the top.
    top = list(reversed(top))

    names = [_short(n) for n, _ in top]
    risks = [rec.get("risk_score", 0.5) for _, rec in top]
    cats  = [rec.get("category", "NO_DATA") for _, rec in top]
    # Deviation from 0.5 midline → signed bar length in [-0.5, +0.5].
    devs  = [r - 0.5 for r in risks]

    fig_h = max(2.8, 0.32 * len(top) + 1.4)
    fig, ax = plt.subplots(figsize=(10, fig_h))

    bar_colors = [CATEGORY_BAR_COLORS.get(c, "#bbbbbb") for c in cats]
    bars = ax.barh(range(len(top)), devs, color=bar_colors,
                   edgecolor="white", linewidth=0.4, height=0.7)

    # Category annotation at bar tip.
    for bar, dev, cat, rec in zip(bars, devs, cats, [r for _, r in top]):
        ratio = rec.get("leak_ratio")
        ratio_txt = f"{ratio:.2f}×" if ratio is not None else "∞"
        label = f"  {cat.replace('_', ' ').title()}  ({ratio_txt})"
        ha = "left" if dev >= 0 else "right"
        x = bar.get_width() + (0.005 if dev >= 0 else -0.005)
        ax.text(x, bar.get_y() + bar.get_height() / 2, label,
                ha=ha, va="center", fontsize=7, color="#444")

    ax.axvline(0, color="black", lw=0.8, alpha=0.7)
    ax.set_yticks(range(len(top)))
    ax.set_yticklabels(names, fontsize=8)
    ax.set_xlim(-0.55, 0.75)   # a little extra right room for labels
    ax.set_xticks([-0.5, -0.25, 0, 0.25, 0.5])
    ax.set_xticklabels(["risk 0.0", "0.25", "0.5\n(neutral)", "0.75", "1.0"],
                       fontsize=8)
    ax.set_xlabel("GLRA risk score (deviation from golden baseline)")

    fam_label = FAMILY_LABELS.get(
        # reuse family lookup for subtitle
        None, "")  # ignored — replaced below
    from config.pipeline_config import get_design_config
    cfg = get_design_config(design)
    fam = cfg.get("trojan_family") or cfg.get("trojan_type") or "unknown"
    fam_label = FAMILY_LABELS.get(fam, fam)
    ax.set_title(
        f"GLRA risk bars — {design}  ·  {fam_label}\n"
        f"Top {len(top)} signals by |risk − 0.5|; red = leakier than golden, "
        f"green = tighter.",
        fontsize=10, fontweight="bold",
    )

    # Compact legend: which categories appeared.
    used_cats = list(dict.fromkeys(cats))  # preserve order
    handles = [mpatches.Patch(facecolor=CATEGORY_BAR_COLORS[c],
                              edgecolor="white",
                              label=c.replace("_", " ").title())
               for c in used_cats if c in CATEGORY_BAR_COLORS]
    if handles:
        ax.legend(handles=handles, loc="upper left",
                  bbox_to_anchor=(1.01, 1.0),
                  fontsize=7, frameon=False, borderaxespad=0)

    # Family-colored left spine as a subtle design-family indicator.
    ax.spines["left"].set_color(color_of(design))
    ax.spines["left"].set_linewidth(2.5)

    fig_dir.mkdir(parents=True, exist_ok=True)
    out_path = fig_dir / f"fig_glra_{design}.png"
    fig.savefig(out_path, bbox_inches="tight", dpi=140)
    plt.close(fig)
    print(f"  [{design}] → {out_path.name} ({len(top)} signals)")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Phase 1 aha viz: GLRA-DFG risk bars per design"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--design", metavar="NAME")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--top-k", type=int, default=20,
                        help="Number of top signals to show per design")
    parser.add_argument("--output-dir", default=None,
                        help="Figures directory (default outputs/figures/)")
    args = parser.parse_args()

    apply_thesis_style()

    pipeline_root = Path(__file__).parent.parent
    output_root   = pipeline_root / "outputs"
    fig_dir       = (Path(args.output_dir) if args.output_dir
                     else output_root / "figures")

    designs = discover_designs() if args.all else [args.design]
    n_ok = n_skip = 0
    for d in designs:
        ok = render_design(d, output_root, fig_dir, top_k=args.top_k)
        n_ok += int(ok)
        n_skip += int(not ok)
    print(f"\nGLRA bars: {n_ok} rendered, {n_skip} skipped (empty/neutral)")


if __name__ == "__main__":
    main()
