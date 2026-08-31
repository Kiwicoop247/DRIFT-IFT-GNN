"""
visualize/style.py — Shared thesis-figure styling.

Single source of truth for colors, fonts and seaborn defaults used by every
figure script (viz_compare.py, future per-design scripts). The palette is
colorblind-safe (Okabe & Ito) and maps to trojan families rather than
individual designs so legends stay compact even with 46+ designs.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import get_design_config

# Okabe & Ito colorblind-safe palette. Ordered so the thesis' headline
# family — power-side-channel — gets the most attention-grabbing hue.
FAMILY_COLORS = {
    "power_side_channel": "#d55e00",  # vermillion  — headline family
    "side_channel":       "#cc79a7",  # reddish-purple
    "data_exfil":         "#0072b2",  # blue
    "power_drain":        "#e69f00",  # orange
    "dos":                "#56b4e9",  # sky blue
    "combinational_trigger":      "#009e73",  # bluish-green
    "sequential_counter_trigger": "#f0e442",  # yellow
    # Comment-derived effect categories for inline (no separate trojan
    # module) designs (config/trojan_categories.json, classify_trojan_effect()).
    # "dos" above is shared deliberately — both taxonomies mean the same thing.
    "leak_info":          "#882255",  # wine        — confidentiality leak (inline, no key/state port)
    "corruption":         "#44aa99",  # teal        — data corruption/zeroing/substitution
    "spoofing":           "#aa4499",  # purple      — status/control spoofing
    "other":              "#999999",  # grey
    "unknown":            "#bbbbbb",  # light grey
}

FAMILY_LABELS = {
    "power_side_channel":          "Power side-channel",
    "side_channel":                "Side-channel",
    "data_exfil":                  "Data exfiltration",
    "power_drain":                 "Power/battery drain",
    "dos":                         "Denial of service",
    "combinational_trigger":       "Combinational trigger",
    "sequential_counter_trigger":  "Sequential counter trigger",
    "leak_info":                   "Leakage (inline)",
    "corruption":                  "Data corruption (inline)",
    "spoofing":                    "Spoofing (inline)",
    "other":                       "Other / unknown leak",
    "unknown":                     "Uncategorised",
}

# Agreement-category palette (kept from the original viz — these map fusion
# categories, not trojan families, and are consumed by stacked bars).
CATEGORY_COLORS = {
    "AGREE_HIGH":    "#117733",   # dark green — both detect
    "AGREE_LOW":     "#dddddd",   # light grey — both clean
    "DFG_ONLY_HIGH": "#332288",   # indigo     — gate-level only
    "AST_ONLY_HIGH": "#cc6677",   # rose       — source-level only (thesis highlight)
    "DIVERGE":       "#882255",   # wine       — disagreement
}

# Styling for the summary-table cells.
TABLE_HEADER_BG     = "#2c3e50"
TABLE_HEADER_FG     = "white"
TABLE_T2100_BG      = "#fdebd0"
TABLE_DETECT_PASS   = "#d5f5e3"
TABLE_DETECT_FAIL   = "#fadbd8"


def family_of(design: str) -> str:
    """Return the trojan family for a design, falling back to 'unknown'.

    Designs with no trojan_types.json entry have trojan_family/trojan_type
    both resolve to "unknown" — fall back to trojan_effect
    (leak_info/dos/corruption/spoofing/other, from the inline comment-marker
    classifier) so they don't all collapse into one flat grey bucket in the
    comparison figures.
    """
    try:
        cfg = get_design_config(design)
    except Exception:
        return "unknown"
    fam = cfg.get("trojan_family") or cfg.get("trojan_type") or "unknown"
    if fam == "unknown":
        fam = cfg.get("trojan_effect") or "unknown"
    return fam if fam in FAMILY_COLORS else "other"


def color_of(design: str) -> str:
    """Return the palette color for a design's trojan family."""
    return FAMILY_COLORS.get(family_of(design), FAMILY_COLORS["unknown"])


def apply_thesis_style() -> None:
    """Apply seaborn + matplotlib defaults for consistent thesis figures.

    Safe to call multiple times. Falls back to pure matplotlib rcParams if
    seaborn is not installed (seaborn is used only for defaults, not APIs).
    """
    import matplotlib as mpl

    try:
        import seaborn as sns
        sns.set_theme(style="whitegrid", context="paper", font_scale=1.0)
    except ImportError:
        pass

    mpl.rcParams.update({
        "figure.dpi":         120,
        "savefig.dpi":        140,
        "savefig.bbox":       "tight",
        "font.family":        "DejaVu Sans",
        "axes.titlesize":     11,
        "axes.titleweight":   "bold",
        "axes.labelsize":     10,
        "axes.spines.top":    False,
        "axes.spines.right":  False,
        "xtick.labelsize":    9,
        "ytick.labelsize":    9,
        "legend.fontsize":    8,
        "legend.frameon":     True,
        "legend.framealpha":  0.9,
        "grid.alpha":         0.25,
    })


def family_legend_handles():
    """matplotlib handles for a 'one entry per family' legend.

    Returns (handles, labels) where handles are Patch objects and labels
    are the human-readable family names. Use `fig.legend(handles, labels)`.
    """
    import matplotlib.patches as mpatches

    handles, labels = [], []
    for fam, color in FAMILY_COLORS.items():
        handles.append(mpatches.Patch(facecolor=color, edgecolor="white"))
        labels.append(FAMILY_LABELS.get(fam, fam))
    return handles, labels
