"""
ablation_weights.py — Weight sensitivity ablation for the QFlow/QtFlow scorers.

Recomputes per-signal scores under ±0.1 weight perturbations using the
already-emitted Stage 2/3 component values in outputs/<DESIGN>/. Avoids
re-running the full pipeline.

Covers:
  • DFG QFlow (Eq. 1): inputs in dfg_nodes.csv (path_score, fanout_score,
    width_score, role → role_bonus).
  • QtFlow DFG (Eq. 4): inputs in qtflow_dfg_scores.json (timing_tainted_*,
    target_cycles, golden_cycles, cycle_delta, ctrl_channels_reached).

Output: LaTeX-ready tables on stdout and to outputs/ablation/.
"""
import csv
import json
from pathlib import Path
from statistics import mean

PIPE_DIR = Path(__file__).resolve().parent.parent  # repository root (this script lives in tools/)
OUT = PIPE_DIR / "outputs"
ABL_OUT = OUT / "ablation"
ABL_OUT.mkdir(exist_ok=True)

DESIGNS = ["AES-T100", "AES-T2100", "AES-T2300", "AES-T2400", "AES-T2500", "AES-T2600"]

# Baseline weights matching pipeline_config.SCORING
DFG_W = {"path": 0.40, "fanout": 0.20, "width": 0.15, "role": 0.25}
# Match role_bonus dict
ROLE_BONUS = {
    "source": 1.0, "sink": 0.9, "trojan": 0.85,
    "key_schedule": 0.7, "timing_sensitive": 0.75,
    "logic": 0.3, "internal": 0.2,
}
# QtFlow TLS weights matching pipeline_config.QTFLOW
QT_W = {"tt": 0.40, "prox": 0.25, "ctrl": 0.20, "dcyc": 0.15}


def perturb(weights: dict, key: str, delta: float) -> dict:
    """Perturb one weight by delta; renormalize the others so total = 1."""
    new = dict(weights)
    new[key] = max(0.0, min(1.0, new[key] + delta))
    others_sum_old = sum(v for k, v in weights.items() if k != key)
    others_sum_new = 1.0 - new[key]
    if others_sum_old > 0:
        for k in weights:
            if k != key:
                new[k] = weights[k] * (others_sum_new / others_sum_old)
    return new


def dfg_qflow_score(row, w):
    role = row.get("role", "internal")
    rb = ROLE_BONUS.get(role, 0.2)
    return (
        w["path"] * float(row.get("path_score", 0) or 0)
        + w["fanout"] * float(row.get("fanout_score", 0) or 0)
        + w["width"] * float(row.get("width_score", 0) or 0)
        + w["role"] * rb
    )


def load_dfg_nodes(design):
    path = OUT / design / "dfg_nodes.csv"
    if not path.exists():
        return []
    rows = list(csv.DictReader(path.open()))
    # Filter to tainted nodes — clean nodes don't move under weight changes
    return [r for r in rows if int(r.get("taint_binary", 0) or 0) == 1]


def dfg_summary(rows, w):
    scores = [dfg_qflow_score(r, w) for r in rows]
    if not scores:
        return None
    high = sum(1 for s in scores if s >= 0.25)
    return {
        "n": len(scores),
        "mean": mean(scores),
        "max": max(scores),
        "n_high": high,
    }


def qtflow_tls(s, w, c_gld):
    t = 1.0 if s.get("timing_tainted_target") else 0.0
    cyc = s.get("target_cycles")
    prox = 1.0 / (1.0 + (cyc if cyc is not None else 64))
    ctrl = min((s.get("ctrl_channels_reached", 0) or 0) / 5.0, 1.0)
    c_tgt = cyc if cyc is not None else 64
    if c_gld and c_gld > 0:
        dcyc = max(0.0, min(1.0, (c_gld - c_tgt) / c_gld))
    else:
        dcyc = 0.0
    tls = w["tt"] * t + w["prox"] * prox + w["ctrl"] * ctrl + w["dcyc"] * dcyc
    return max(0.0, min(1.0, tls))


def qtflow_summary(d, w):
    if not d:
        return None
    tls_vals = []
    n_inj = 0
    for sig, s in d.items():
        c_gld = s.get("golden_cycles") or 0
        tls = qtflow_tls(s, w, c_gld)
        tls_vals.append(tls)
        if s.get("timing_tainted_target") and not s.get("timing_tainted_golden"):
            n_inj += 1
    return {
        "n": len(tls_vals),
        "mean_tls": mean(tls_vals),
        "max_tls": max(tls_vals),
        "n_inj": n_inj,
    }


def fmt_pct_change(new, base):
    if base == 0:
        return "—"
    pct = (new - base) / base * 100
    sign = "+" if pct >= 0 else ""
    return f"{sign}{pct:.1f}\\%"


def main():
    print("=" * 70)
    print("DFG QFlow weight ablation (Eq. 1) — mean score and # signals ≥ 0.25")
    print("=" * 70)

    # Per-design results, all 4 weights, ±0.1
    perturbations = []
    for key in ["path", "fanout", "width", "role"]:
        for delta in (-0.10, +0.10):
            perturbations.append((key, delta))

    dfg_rows = {d: load_dfg_nodes(d) for d in DESIGNS}
    baseline_per_design = {
        d: dfg_summary(rows, DFG_W) for d, rows in dfg_rows.items()
    }

    print("\nBaseline (w_path=0.40, w_fanout=0.20, w_width=0.15, w_role=0.25):")
    for d, b in baseline_per_design.items():
        if b:
            print(f"  {d}: n={b['n']}, mean={b['mean']:.3f}, "
                  f"max={b['max']:.3f}, n≥0.25={b['n_high']}")

    print("\nPerturbations:")
    dfg_table = []
    for key, delta in perturbations:
        new_w = perturb(DFG_W, key, delta)
        line_design = []
        for d in DESIGNS:
            new = dfg_summary(dfg_rows[d], new_w)
            base = baseline_per_design[d]
            if new and base:
                delta_high = new["n_high"] - base["n_high"]
                line_design.append((d, new["mean"], new["n_high"], delta_high))
        dfg_table.append((key, delta, new_w, line_design))
        sign = "+" if delta > 0 else ""
        print(f"\nW_{key.upper()} {sign}{delta:+.2f} "
              f"(weights now: path={new_w['path']:.3f}, fanout={new_w['fanout']:.3f}, "
              f"width={new_w['width']:.3f}, role={new_w['role']:.3f})")
        for d, m, h, dh in line_design:
            print(f"    {d}: mean={m:.3f}, n≥0.25={h} (Δ {dh:+d})")

    # Build LaTeX table for DFG QFlow ablation
    latex_dfg = build_latex_dfg(baseline_per_design, dfg_table)
    (ABL_OUT / "dfg_qflow_ablation.tex").write_text(latex_dfg)
    print(f"\nWrote {ABL_OUT / 'dfg_qflow_ablation.tex'}")

    # QtFlow TLS ablation
    print("\n" + "=" * 70)
    print("QtFlow DFG TLS weight ablation (Eq. 4) — mean TLS and # TIMING_INJECTED")
    print("=" * 70)

    qt_data = {}
    for d in DESIGNS:
        f = OUT / d / "qtflow_dfg_scores.json"
        if f.exists():
            qt_data[d] = json.load(f.open())
        else:
            qt_data[d] = {}

    baseline_qt = {d: qtflow_summary(qt_data[d], QT_W) for d in DESIGNS}
    print("\nBaseline (w_tt=0.40, w_prox=0.25, w_ctrl=0.20, w_dcyc=0.15):")
    for d, b in baseline_qt.items():
        if b:
            print(f"  {d}: n={b['n']}, mean_tls={b['mean_tls']:.3f}, "
                  f"max_tls={b['max_tls']:.3f}, n_inj={b['n_inj']}")

    qt_perturbations = []
    for key in ["tt", "prox", "ctrl", "dcyc"]:
        for delta in (-0.10, +0.10):
            qt_perturbations.append((key, delta))

    qt_table = []
    for key, delta in qt_perturbations:
        new_w = perturb(QT_W, key, delta)
        line_design = []
        for d in DESIGNS:
            new = qtflow_summary(qt_data[d], new_w)
            base = baseline_qt[d]
            if new and base:
                line_design.append((d, new["mean_tls"], new["n_inj"],
                                    new["n_inj"] - base["n_inj"]))
        qt_table.append((key, delta, new_w, line_design))
        sign = "+" if delta > 0 else ""
        print(f"\nW_{key.upper()} {sign}{delta:+.2f} "
              f"(tt={new_w['tt']:.3f}, prox={new_w['prox']:.3f}, "
              f"ctrl={new_w['ctrl']:.3f}, dcyc={new_w['dcyc']:.3f})")
        for d, m, n_inj, dn in line_design:
            print(f"    {d}: mean_tls={m:.3f}, n_inj={n_inj} (Δ {dn:+d})")

    latex_qt = build_latex_qt(baseline_qt, qt_table)
    (ABL_OUT / "qtflow_tls_ablation.tex").write_text(latex_qt)
    print(f"\nWrote {ABL_OUT / 'qtflow_tls_ablation.tex'}")


SHORT_NAMES = [d.replace("AES-", "") for d in DESIGNS]
NCOL = len(DESIGNS)


def build_latex_dfg(baseline, table):
    lines = []
    lines.append(r"\begin{table}[h]")
    lines.append(r"\centering")
    lines.append(r"\caption{DFG QFlow weight sensitivity (Equation~\ref{eq:qflow}). "
                 r"Each row perturbs one weight by $\pm 0.10$; the remaining three "
                 r"weights are renormalised proportionally. Reported: mean per-signal "
                 r"score and number of signals scoring $\geq 0.25$ on the full "
                 r"six-design deep-dive subset.}")
    lines.append(r"\label{tab:ablation_dfg_qflow}")
    lines.append(r"\begin{adjustbox}{max width=\linewidth}")
    lines.append(r"\begin{tabular}{l " + " ".join(["r"] * (2 * NCOL)) + "}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Perturbation}"
                 rf" & \multicolumn{{{NCOL}}}{{c}}{{\textbf{{mean score}}}}"
                 rf" & \multicolumn{{{NCOL}}}{{c}}{{$\boldsymbol{{n \geq 0.25}}$}} \\")
    lines.append(" & " + " & ".join(SHORT_NAMES)
                 + " & " + " & ".join(SHORT_NAMES) + r" \\")
    lines.append(r"\midrule")

    def row_baseline():
        means = " & ".join(
            f"{baseline[d]['mean']:.3f}" if baseline[d] else "--"
            for d in DESIGNS
        )
        highs = " & ".join(
            f"{baseline[d]['n_high']}" if baseline[d] else "--"
            for d in DESIGNS
        )
        return f"Baseline & {means} & {highs} \\\\"

    lines.append(row_baseline())
    lines.append(r"\midrule")
    for key, delta, _w, perd in table:
        label = f"$w_{{{key}}}\\;{delta:+.2f}$"
        means = " & ".join(f"{m:.3f}" for _d, m, _h, _dh in perd)
        highs = " & ".join(f"{h}~({dh:+d})" for _d, _m, h, dh in perd)
        lines.append(f"{label} & {means} & {highs} \\\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{adjustbox}")
    lines.append(r"\end{table}")
    return "\n".join(lines) + "\n"


def build_latex_qt(baseline, table):
    lines = []
    lines.append(r"\begin{table}[h]")
    lines.append(r"\centering")
    lines.append(r"\caption{QtFlow DFG TLS weight sensitivity (Equation~\ref{eq:tls}). "
                 r"Each row perturbs one weight by $\pm 0.10$; the remaining three "
                 r"weights are renormalised. Reported: mean per-signal TLS and number "
                 r"of \textsc{timing\_injected} signals on the full six-design "
                 r"deep-dive subset.}")
    lines.append(r"\label{tab:ablation_qtflow_tls}")
    lines.append(r"\begin{adjustbox}{max width=\linewidth}")
    lines.append(r"\begin{tabular}{l " + " ".join(["r"] * (2 * NCOL)) + "}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Perturbation}"
                 rf" & \multicolumn{{{NCOL}}}{{c}}{{\textbf{{mean TLS}}}}"
                 rf" & \multicolumn{{{NCOL}}}{{c}}{{$\boldsymbol{{n_{{\text{{TIMING\_INJECTED}}}}}}$}} \\")
    lines.append(" & " + " & ".join(SHORT_NAMES)
                 + " & " + " & ".join(SHORT_NAMES) + r" \\")
    lines.append(r"\midrule")

    means_b = " & ".join(
        f"{baseline[d]['mean_tls']:.3f}" if baseline[d] else "--"
        for d in DESIGNS
    )
    injs_b = " & ".join(
        f"{baseline[d]['n_inj']}" if baseline[d] else "--"
        for d in DESIGNS
    )
    lines.append(f"Baseline & {means_b} & {injs_b} \\\\")
    lines.append(r"\midrule")
    for key, delta, _w, perd in table:
        label_key = {"tt": r"\text{tt}", "prox": r"\text{prox}",
                     "ctrl": r"\text{ctrl}", "dcyc": r"\Delta c"}[key]
        label = f"$w_{{{label_key}}}\\;{delta:+.2f}$"
        means = " & ".join(f"{m:.3f}" for _d, m, _i, _di in perd)
        injs = " & ".join(f"{i}~({di:+d})" for _d, _m, i, di in perd)
        lines.append(f"{label} & {means} & {injs} \\\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{adjustbox}")
    lines.append(r"\end{table}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
