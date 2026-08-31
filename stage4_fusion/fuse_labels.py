"""
stage4_fusion/fuse_labels.py — Fuse DFG + AST taint scores (Stage 4)

Merges taint_scores.json (DFG) + ast_taint_scores.json (AST) +
golden_scores.json (golden baseline) into a single combined_labels.json
with per-signal agreement categories and GNN-ready features.

Agreement categories:
  AGREE_HIGH    — both DFG ≥ 0.25 and AST ≥ 0.25 (within threshold)
  AGREE_LOW     — both below threshold → confidently clean
  DFG_ONLY_HIGH — DFG high, AST low (synthesis artefact)
  AST_ONLY_HIGH — AST high, DFG low (dead code / power-only Trojan)
  DIVERGE       — both tainted but very different scores

This is the key output for the thesis argument:
  T2100 power-side-channel → SECRETKey/COUNTER/LEAKBit in AST_ONLY_HIGH
  T2300/T2400 combinational triggers → AGREE_HIGH
  T2500 pure-clock counter → AGREE_LOW (both analyses miss it)

Outputs:
  outputs/{DESIGN}/combined_labels.json
  outputs/{DESIGN}/fusion_report.txt

Usage:
    python3 stage4_fusion/fuse_labels.py --design AES-T2100
    python3 stage4_fusion/fuse_labels.py --all
"""

import sys
import json
import argparse
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import (
    get_design_config,
    discover_designs,
    FUSION_THRESHOLDS,
)

AGREE_THRESH      = FUSION_THRESHOLDS["AGREE_THRESH"]       # |DFG − AST| within this → agreement
HIGH_THRESH       = FUSION_THRESHOLDS["HIGH_THRESH"]        # score ≥ this → "high" (both-agree threshold)
AST_DETECT_THRESH = FUSION_THRESHOLDS["AST_DETECT_THRESH"]  # AST-only detection floor; captures
                                                            # power-channel signals (score ~0.10-0.15)
                                                            # that DFG drops to 0 via synthesis dead-code removal
ANOMALY_DELTA     = FUSION_THRESHOLDS["ANOMALY_DELTA"]      # |delta_score| > this → is_anomaly=1


def _glra_fields(entry: dict | None) -> dict:
    """Return the GLRA-DFG sub-fields for a combined_labels entry.

    Missing/empty GLRA → neutral defaults (risk=0.5, category=NO_CHANGE)
    so a design without GLRA data looks like 'no perturbation' rather than
    zero (which would look like 'safer than baseline', incorrect).
    """
    if not entry:
        return {
            "glra_dfg_risk":     0.5,
            "glra_dfg_ratio":    None,
            "glra_dfg_category": "NO_DATA",
        }
    return {
        "glra_dfg_risk":     entry.get("risk_score", 0.5),
        "glra_dfg_ratio":    entry.get("leak_ratio"),
        "glra_dfg_category": entry.get("category", "NO_DATA"),
    }


def _qtflow_dfg_fields(entry: dict | None) -> dict:
    """QtFlow-DFG (Phase 2) sub-fields. Neutral defaults when file absent."""
    if not entry:
        return {
            "qtflow_dfg_tls":      0.5,
            "qtflow_dfg_cycles":   None,
            "qtflow_dfg_ctrl_n":   0,
            "qtflow_dfg_category": "NO_DATA",
        }
    return {
        "qtflow_dfg_tls":      entry.get("tls", 0.5),
        "qtflow_dfg_cycles":   entry.get("target_cycles"),
        "qtflow_dfg_ctrl_n":   entry.get("ctrl_channels_reached", 0),
        "qtflow_dfg_category": entry.get("category", "NO_DATA"),
    }


def _qtflow_ast_fields(entry: dict | None) -> dict:
    """QtFlow-AST (Phase 2b) sub-fields. Neutral defaults when file absent."""
    if not entry:
        return {
            "qtflow_ast_tls":      0.5,
            "qtflow_ast_cycles":   None,
            "qtflow_ast_ctrl_n":   0,
            "qtflow_ast_category": "NO_DATA",
        }
    return {
        "qtflow_ast_tls":      entry.get("tls", 0.5),
        "qtflow_ast_cycles":   entry.get("target_cycles"),
        "qtflow_ast_ctrl_n":   entry.get("ctrl_channels_reached", 0),
        "qtflow_ast_category": entry.get("category", "NO_DATA"),
    }


def _short_name(name: str) -> str:
    """
    Reduce a hierarchical Yosys net name to its signal name.
    e.g. '$flatten\\Trojan.SECRETKey' → 'SECRETKey'
         'a1.v0' → 'v0' ... but keep 'key', 'state', 'out' as-is.
    """
    clean = name.replace("\\", ".")
    parts = [p for p in clean.split(".") if p and not p.startswith("$")]
    return parts[-1] if parts else name


def fuse(design_name: str, force: bool = False, variant: str = "tjin") -> dict:
    cfg = get_design_config(design_name, variant=variant)
    output_dir = Path(cfg["output_dir"])

    out_combined = output_dir / "combined_labels.json"
    out_report   = output_dir / "fusion_report.txt"
    if out_combined.exists() and not force:
        print(f"[{design_name}] combined_labels.json exists — skipping (use --force)")
        with open(out_combined) as f:
            return json.load(f)

    # ── Load inputs ───────────────────────────────────────────────────────────
    dfg_path  = output_dir / "taint_scores.json"
    ast_path  = output_dir / "ast_taint_scores.json"
    gold_path = output_dir / "golden_scores.json"

    if not dfg_path.exists():
        raise FileNotFoundError(f"taint_scores.json missing — run dfg_taint.py first")
    if not ast_path.exists():
        raise FileNotFoundError(f"ast_taint_scores.json missing — run run_ast.py first")

    with open(dfg_path) as f:
        dfg_full = json.load(f)
    with open(ast_path) as f:
        ast_data = json.load(f)
    has_golden = gold_path.exists()
    golden = {}
    if has_golden:
        with open(gold_path) as f:
            golden = json.load(f)

    # Optional GLRA-DFG scores (Phase 1 — additive, does not affect category).
    glra_dfg_path = output_dir / "glra_dfg_scores.json"
    glra_dfg: dict[str, dict] = {}
    if glra_dfg_path.exists():
        with open(glra_dfg_path) as f:
            glra_raw = json.load(f)
        # Normalise to short signal names (same rule as dfg_short below):
        # multiple hierarchical entries can collapse onto one short name —
        # keep the highest risk_score (strongest GLRA signal wins).
        for full_name, sc in glra_raw.items():
            short = _short_name(full_name)
            existing = glra_dfg.get(short)
            if existing is None or sc["risk_score"] > existing["risk_score"]:
                glra_dfg[short] = {**sc, "_full_name": full_name}

    # Optional QtFlow-DFG scores (Phase 2 — timing-sensitive, additive).
    qtflow_dfg_path = output_dir / "qtflow_dfg_scores.json"
    qtflow_dfg: dict[str, dict] = {}
    if qtflow_dfg_path.exists():
        with open(qtflow_dfg_path) as f:
            qtflow_raw = json.load(f)
        # Highest-TLS-wins on short-name collisions (same pattern as GLRA).
        for full_name, sc in qtflow_raw.items():
            short = _short_name(full_name)
            existing = qtflow_dfg.get(short)
            if existing is None or sc.get("tls", 0.0) > existing.get("tls", 0.0):
                qtflow_dfg[short] = {**sc, "_full_name": full_name}

    # Optional QtFlow-AST scores (Phase 2b — source-level timing-sensitive).
    qtflow_ast_path = output_dir / "qtflow_ast_scores.json"
    qtflow_ast: dict[str, dict] = {}
    if qtflow_ast_path.exists():
        with open(qtflow_ast_path) as f:
            qtflow_ast_raw = json.load(f)
        # AST already uses bare signal names — no short-name normalisation
        # needed. But still dedupe in case of hierarchical accidents.
        for full_name, sc in qtflow_ast_raw.items():
            short = _short_name(full_name)
            existing = qtflow_ast.get(short)
            if existing is None or sc.get("tls", 0.0) > existing.get("tls", 0.0):
                qtflow_ast[short] = {**sc, "_full_name": full_name}

    # ── Normalise DFG keys to short signal names ──────────────────────────────
    # Many DFG nodes have names like '$flatten\Trojan.SECRETKey' — keep only
    # the highest-scoring entry for each short name.
    dfg_short: dict[str, dict] = {}
    for full_name, sc in dfg_full.items():
        short = _short_name(full_name)
        if short not in dfg_short or sc["taint_score"] > dfg_short[short]["taint_score"]:
            dfg_short[short] = {**sc, "_full_name": full_name}

    print(f"[{design_name}] DFG: {len(dfg_full)} nodes → {len(dfg_short)} unique names | "
          f"AST: {len(ast_data)} | Golden: {len(golden) if has_golden else 'N/A'}")

    common   = set(dfg_short.keys()) & set(ast_data.keys())
    dfg_only = set(dfg_short.keys()) - set(ast_data.keys())
    ast_only = set(ast_data.keys()) - set(dfg_short.keys())

    # ── Classify common signals ───────────────────────────────────────────────
    def get_golden_score(sig: str) -> tuple[float, int]:
        """Return (golden_taint_score, golden_taint_binary) for a signal."""
        if not has_golden:
            return 0.0, 0
        if sig in golden:
            return golden[sig].get("taint_score", 0.0), golden[sig].get("taint_binary", 0)
        # Try case-insensitive match
        lower = sig.lower()
        for g_sig, g_data in golden.items():
            if g_sig.lower() == lower:
                return g_data.get("taint_score", 0.0), g_data.get("taint_binary", 0)
        return 0.0, 0

    combined: dict[str, dict] = {}

    for sig in common:
        d = dfg_short[sig]
        a = ast_data[sig]

        d_score = d["taint_score"]
        a_score = a["taint_score"]
        diff    = abs(d_score - a_score)
        d_high  = d_score >= HIGH_THRESH
        a_high  = a_score >= HIGH_THRESH

        # "AST-only detection": AST sees it, DFG is blind (synthesis dead-code removal).
        # Use a lower absolute threshold (AST_DETECT_THRESH) AND require DFG to be
        # less than half the AST score, capturing power-channel signals (score ~0.10-0.15)
        # that synthesis removes entirely.
        a_detects = a_score >= AST_DETECT_THRESH
        d_detects = d_score >= AST_DETECT_THRESH
        dfg_blind  = d_score < a_score * 0.5

        if d_high and a_high and diff <= AGREE_THRESH:
            category = "AGREE_HIGH"
        elif d_detects and a_detects and not dfg_blind and not d_high and not a_high:
            category = "AGREE_LOW"       # both see it weakly but agree
        elif not d_detects and not a_detects:
            category = "AGREE_LOW"       # both say clean
        elif d_high and not a_detects:
            category = "DFG_ONLY_HIGH"
        elif a_detects and dfg_blind:
            category = "AST_ONLY_HIGH"   # AST sees it, DFG is blind
        else:
            category = "DIVERGE"

        # Combined score: average when agree, max when diverge
        if category in ("AGREE_HIGH", "AGREE_LOW"):
            combined_score = (d_score + a_score) / 2.0
            confidence     = 1.0 - diff
        else:
            combined_score = max(d_score, a_score)
            confidence     = max(0.0, 0.5 - diff * 0.5)

        on_trojan = int(
            d.get("is_on_trojan_path", 0) or a.get("is_on_trojan_path", 0)
        )

        golden_score, golden_tainted = get_golden_score(sig)
        delta_score = round(d_score - golden_score, 4)
        if golden_tainted == 0 and d.get("taint_binary", 0) == 1:
            delta_cat = "INJECTED"
        elif delta_score > 0.2:
            delta_cat = "ELEVATED"
        elif delta_score < -0.2:
            delta_cat = "SUPPRESSED"
        else:
            delta_cat = "NO_CHANGE"

        combined[sig] = {
            "dfg_score":         round(d_score, 4),
            "ast_score":         round(a_score, 4),
            "combined_score":    round(combined_score, 4),
            "confidence":        round(confidence, 4),
            "diff":              round(diff, 4),
            "category":          category,
            "dfg_role":          d.get("role", "?"),
            "ast_role":          a.get("role", "?"),
            "timing_sensitive":  int(a.get("timing_sensitive", 0)),
            "is_on_trojan_path": on_trojan,
            "dfg_tainted":       d.get("taint_binary", 0),
            "ast_tainted":       a.get("taint_binary", 0),
            "golden_score":      round(golden_score, 4),
            "golden_tainted":    golden_tainted,
            "delta_score":       delta_score,
            "delta_category":    delta_cat,
            "is_injected":       1 if delta_cat == "INJECTED" else 0,
            "is_anomaly":        1 if abs(delta_score) > ANOMALY_DELTA else 0,
            **_glra_fields(glra_dfg.get(sig)),
            **_qtflow_dfg_fields(qtflow_dfg.get(sig)),
            **_qtflow_ast_fields(qtflow_ast.get(sig)),
        }

    # DFG-only signals
    for sig in dfg_only:
        d = dfg_short[sig]
        golden_score, golden_tainted = get_golden_score(sig)
        delta_score = round(d["taint_score"] - golden_score, 4)
        delta_cat = ("INJECTED" if golden_tainted == 0 and d.get("taint_binary", 0) == 1
                     else "NO_CHANGE")
        combined[sig] = {
            "dfg_score":         round(d["taint_score"], 4),
            "ast_score":         0.0,
            "combined_score":    round(d["taint_score"] * 0.7, 4),
            "confidence":        0.4,
            "diff":              d["taint_score"],
            "category":          "DFG_ONLY",
            "dfg_role":          d.get("role", "?"),
            "ast_role":          "not_in_ast",
            "timing_sensitive":  0,
            "is_on_trojan_path": d.get("is_on_trojan_path", 0),
            "dfg_tainted":       d.get("taint_binary", 0),
            "ast_tainted":       0,
            "golden_score":      round(golden_score, 4),
            "golden_tainted":    golden_tainted,
            "delta_score":       delta_score,
            "delta_category":    delta_cat,
            "is_injected":       1 if delta_cat == "INJECTED" else 0,
            "is_anomaly":        1 if abs(delta_score) > ANOMALY_DELTA else 0,
            **_glra_fields(glra_dfg.get(sig)),
            **_qtflow_dfg_fields(qtflow_dfg.get(sig)),
            **_qtflow_ast_fields(qtflow_ast.get(sig)),
        }

    # AST-only signals
    for sig in ast_only:
        a = ast_data[sig]
        golden_score, golden_tainted = get_golden_score(sig)
        delta_score = round(a["taint_score"] - golden_score, 4)
        delta_cat = ("INJECTED" if golden_tainted == 0 and a.get("taint_binary", 0) == 1
                     else "NO_CHANGE")
        combined[sig] = {
            "dfg_score":         0.0,
            "ast_score":         round(a["taint_score"], 4),
            "combined_score":    round(a["taint_score"] * 0.7, 4),
            "confidence":        0.4,
            "diff":              a["taint_score"],
            "category":          "AST_ONLY",
            "dfg_role":          "not_in_dfg",
            "ast_role":          a.get("role", "?"),
            "timing_sensitive":  a.get("timing_sensitive", 0),
            "is_on_trojan_path": a.get("is_on_trojan_path", 0),
            "dfg_tainted":       0,
            "ast_tainted":       a.get("taint_binary", 0),
            "golden_score":      round(golden_score, 4),
            "golden_tainted":    golden_tainted,
            "delta_score":       delta_score,
            "delta_category":    delta_cat,
            "is_injected":       1 if delta_cat == "INJECTED" else 0,
            "is_anomaly":        1 if abs(delta_score) > ANOMALY_DELTA else 0,
            **_glra_fields(glra_dfg.get(sig)),
            **_qtflow_dfg_fields(qtflow_dfg.get(sig)),
            **_qtflow_ast_fields(qtflow_ast.get(sig)),
        }

    # ── Save combined_labels.json ─────────────────────────────────────────────
    with open(out_combined, "w") as f:
        json.dump(combined, f, indent=2)

    # ── Report ────────────────────────────────────────────────────────────────
    cat_counts: dict[str, list] = defaultdict(list)
    for sig, r in combined.items():
        cat_counts[r["category"]].append(sig)

    ast_only_high = [s for s in combined
                     if combined[s]["category"] == "AST_ONLY_HIGH"]
    ast_only_high.sort(key=lambda s: combined[s]["ast_score"], reverse=True)

    timing_tainted = [s for s in combined
                      if combined[s]["timing_sensitive"]
                      and (combined[s]["dfg_tainted"] or combined[s]["ast_tainted"])]

    trojan_type = cfg.get("trojan_type", "unknown")
    report_lines = [
        f"FUSION REPORT — {design_name}", "=" * 60,
        f"Trojan type      : {trojan_type}",
        f"Common signals   : {len(common)}",
        f"DFG-only         : {len(dfg_only)}",
        f"AST-only         : {len(ast_only)}",
        f"Total combined   : {len(combined)}",
        "", "CATEGORY BREAKDOWN", "-" * 40,
        f"  AGREE_HIGH     : {len(cat_counts['AGREE_HIGH'])}",
        f"  AGREE_LOW      : {len(cat_counts['AGREE_LOW'])}",
        f"  DFG_ONLY_HIGH  : {len(cat_counts['DFG_ONLY_HIGH'])}",
        f"  AST_ONLY_HIGH  : {len(cat_counts['AST_ONLY_HIGH'])}",
        f"  DIVERGE        : {len(cat_counts['DIVERGE'])}",
        f"  DFG_ONLY       : {len(cat_counts['DFG_ONLY'])}",
        f"  AST_ONLY       : {len(cat_counts['AST_ONLY'])}",
        "", "KEY TROJAN SIGNALS", "-" * 40,
    ]

    for sig in ["key", "state", "SECRETKey", "LEAKBit", "Tj_Trig",
                "COUNTER", "trigger", "out"]:
        if sig in combined:
            r = combined[sig]
            report_lines.append(
                f"  {sig:<20} DFG={r['dfg_score']:.3f}  "
                f"AST={r['ast_score']:.3f}  "
                f"cat={r['category']:<15}  "
                f"timing={r['timing_sensitive']}"
            )

    report_lines += ["", "AST_ONLY_HIGH SIGNALS (Yosys removed — key thesis finding)", "-" * 40]
    for sig in ast_only_high:
        r = combined[sig]
        report_lines.append(
            f"  {sig:<25} AST={r['ast_score']:.3f}  "
            f"role={r['ast_role']}  timing={r['timing_sensitive']}"
        )

    report_lines += ["", f"TIMING-SENSITIVE TAINTED SIGNALS: {len(timing_tainted)}", "-" * 40]
    for sig in timing_tainted:
        r = combined[sig]
        report_lines.append(
            f"  {sig:<25} DFG={r['dfg_score']:.3f}  AST={r['ast_score']:.3f}"
        )

    with open(out_report, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    n_ast_only_high = len(cat_counts["AST_ONLY_HIGH"])
    n_agree_high    = len(cat_counts["AGREE_HIGH"])
    print(f"[{design_name}] → combined_labels.json ({len(combined)} signals) | "
          f"AGREE_HIGH={n_agree_high} AST_ONLY_HIGH={n_ast_only_high} | "
          f"fusion_report.txt")

    return combined


def main():
    parser = argparse.ArgumentParser(description="Stage 4: Fuse DFG + AST labels")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--design", metavar="NAME")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--force", action="store_true",
                        help="Recompute even if outputs exist")
    args = parser.parse_args()

    designs = discover_designs() if args.all else [args.design]
    errors = []
    for name in designs:
        try:
            fuse(name, force=args.force)
        except Exception as e:
            print(f"[{name}] ERROR: {e}")
            errors.append(name)

    if errors:
        print(f"\nFailed: {errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
