"""
stage5_export/hw2vec_export.py — GNN-ready export (Stage 5)

Converts the fused combined_labels.json + dfg_nodes.csv + dfg_edges.csv
into PyTorch Geometric / HW2VEC compatible numpy arrays:

  node_features.npy   — shape (N, 14), float32, all values in [0, 1]
  edge_index.npy      — shape (2, E), int64 (COO format)
  labels.npy          — shape (N,), int64, {0=clean, 1=trojan}
  metadata.json       — node names, feature names, design info

Node feature vector (14 dimensions — features 0-10 stable across Phases):
  0  taint_score        — DFG quantitative score
  1  ast_score          — AST quantitative score
  2  combined_score     — fused score
  3  is_on_trojan_path  — DFG reverse-BFS from trojan sink
  4  timing_sensitive   — in tainted always block sensitivity list (AST)
  5  role_enc_norm      — role encoding normalised to [0,1]
  6  cell_type_enc      — cell type category encoded (0–1)
  7  width_norm         — signal width / 128
  8  dist_source_norm   — 1/(1+dist) normalised path length
  9  delta_score        — |full IFT − golden| (trojan perturbation)
  10 is_injected        — new taint in trojan vs golden (binary)
  11 glra_dfg_risk      — GLRA normalised risk [0,1] (Phase 1)
  12 qtflow_dfg_tls     — QtFlow DFG Timing Leakage Score [0,1] (Phase 2)
  13 qtflow_ast_tls     — QtFlow AST Timing Leakage Score [0,1] (Phase 2b)

Label rule:
  A node is labelled trojan=1 if:
    - it has a trojan_intermediate role, OR
    - it is in a trojan-named hierarchy (Trojan.*, $flatten\\Trojan.*), OR
    - its delta_score > 0.05 and is_injected=1

Usage:
    python3 stage5_export/hw2vec_export.py --design AES-T2100
    python3 stage5_export/hw2vec_export.py --all
"""

import sys
import json
import csv
import argparse
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))
from stage3_scoring.golden_delta import _make_trojan_predicate

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import (
    get_design_config,
    discover_designs,
    ROLE_ENC_NORM,
)

# Cell type → category encoding (0.0 – 1.0)
CELL_TYPE_ENC = {
    "port":     0.0,
    "net":      0.05,
    "$xor":     0.2,
    "$xnor":    0.2,
    "$or":      0.2,
    "$nor":     0.2,
    "$not":     0.2,
    "$buf":     0.2,
    "$and":     0.4,
    "$nand":    0.4,
    "$mux":     0.6,
    "$eq":      0.65,
    "$ne":      0.65,
    "$lt":      0.65,
    "$le":      0.65,
    "$add":     0.7,
    "$sub":     0.7,
    "$dff":     0.85,
    "$adff":    0.85,
    "$aldff":   0.85,
    "$sdff":    0.85,
    "logic":    0.1,
}

TROJAN_PREFIXES = ("Trojan.", "$flatten\\Trojan.", "Trigger.",
                   "$flatten\\Trigger.")


def _cell_type_to_enc(cell_type: str) -> float:
    ct = cell_type.lower()
    for key, val in CELL_TYPE_ENC.items():
        if key in ct:
            return val
    return 0.1


def _is_trojan_node(name: str, role: str) -> bool:
    if role == "trojan_intermediate":
        return True
    if any(name.startswith(p) for p in TROJAN_PREFIXES):
        return True
    return False


def export(design_name: str, force: bool = False, variant: str = "tjin") -> None:
    cfg = get_design_config(design_name, variant=variant)
    output_dir = Path(cfg["output_dir"])
    _is_trojan_pattern = _make_trojan_predicate(cfg["trojan_patterns"])

    hw2vec_dir = output_dir / "hw2vec"
    out_features = hw2vec_dir / "node_features.npy"
    out_edges    = hw2vec_dir / "edge_index.npy"
    out_labels   = hw2vec_dir / "labels.npy"
    out_graph_label = hw2vec_dir / "graph_label.npy"
    out_meta     = hw2vec_dir / "metadata.json"

    if out_features.exists() and not force:
        print(f"[{design_name}] hw2vec/ exists — skipping (use --force)")
        return

    # ── Load DFG nodes ─────────────────────────────────────────────────────────
    dfg_nodes_path = output_dir / "dfg_nodes.csv"
    if not dfg_nodes_path.exists():
        raise FileNotFoundError(f"dfg_nodes.csv missing — run dfg_taint.py first")

    dfg_nodes: dict[str, dict] = {}
    with open(dfg_nodes_path) as f:
        for row in csv.DictReader(f):
            dfg_nodes[row["node_name"]] = row

    # ── Load DFG edges ─────────────────────────────────────────────────────────
    dfg_edges_path = output_dir / "dfg_edges.csv"
    edges_raw: list[tuple[int, int]] = []
    with open(dfg_edges_path) as f:
        for row in csv.DictReader(f):
            edges_raw.append((int(row["src_id"]), int(row["dst_id"])))

    # ── Load combined labels ───────────────────────────────────────────────────
    combined_path = output_dir / "combined_labels.json"
    combined: dict[str, dict] = {}
    if combined_path.exists():
        with open(combined_path) as f:
            combined = json.load(f)

    # ── Load delta scores ──────────────────────────────────────────────────────
    delta_path = output_dir / "delta_scores.json"
    delta: dict[str, dict] = {}
    if delta_path.exists():
        with open(delta_path) as f:
            delta = json.load(f)

    node_names = list(dfg_nodes.keys())
    N = len(node_names)
    print(f"[{design_name}] Building feature matrix: {N} nodes, {len(edges_raw)} edges")

    features = np.zeros((N, 14), dtype=np.float32)
    labels   = np.zeros(N, dtype=np.int64)

    # Short name lookup for combined_labels (which uses short names)
    def _short(name: str) -> str:
        clean = name.replace("\\", ".")
        parts = [p for p in clean.split(".") if p and not p.startswith("$")]
        return parts[-1] if parts else name

    for i, node_name in enumerate(node_names):
        row = dfg_nodes[node_name]
        short = _short(node_name)
        fused = combined.get(short, {})
        dsc   = delta.get(node_name, delta.get(short, {}))

        # 0: DFG taint score
        features[i, 0] = float(row.get("taint_score", 0))
        # 1: AST taint score
        features[i, 1] = float(fused.get("ast_score", 0))
        # 2: combined score
        features[i, 2] = float(fused.get("combined_score", features[i, 0]))
        # 3: is_on_trojan_path
        features[i, 3] = float(row.get("is_on_trojan_path", 0))
        # 4: timing_sensitive (from AST)
        features[i, 4] = float(fused.get("timing_sensitive", 0))
        # 5: role_enc normalised
        role = row.get("role", "internal")
        features[i, 5] = ROLE_ENC_NORM.get(role, 0.1)
        # 6: cell_type encoding
        features[i, 6] = _cell_type_to_enc(row.get("cell_type", "net"))
        # 7: width normalised to 128-bit
        width = float(row.get("width", 1))
        features[i, 7] = min(width / 128.0, 1.0)
        # 8: distance from source (1/(1+d) path length)
        d_src = int(row.get("dist_source", -1))
        features[i, 8] = 1.0 / (1.0 + max(d_src, 0)) if d_src >= 0 else 0.0
        # 9: delta score (|full − golden|), normalised
        features[i, 9]  = min(abs(float(dsc.get("delta_taint_score", 0))), 1.0)
        # 10: is_injected
        features[i, 10] = float(dsc.get("delta_binary", fused.get("is_injected", 0)))
        # 11: GLRA-DFG normalised risk (Phase 1). Defaults to 0.5 (neutral) when
        # the signal has no GLRA data — treating it as "no perturbation" rather
        # than 0 (which would look like "safer than baseline", incorrect).
        features[i, 11] = float(fused.get("glra_dfg_risk", 0.5))
        # 12: QtFlow DFG timing leakage score (Phase 2). Neutral-0.5 default.
        features[i, 12] = float(fused.get("qtflow_dfg_tls", 0.5))
        # 13: QtFlow AST timing leakage score (Phase 2b). Neutral-0.5 default.
        features[i, 13] = float(fused.get("qtflow_ast_tls", 0.5))

        # Label: trojan if role=trojan_intermediate OR hierarchical trojan name
        # OR high delta and injected OR Stage 4 fusion already found it via
        # the AST-only path. This last condition matters beyond the legacy
        # T2100 case it was originally written for (ghost_tainted
        # force-marks that node's role directly, so it was already covered
        # by _is_trojan_node without this): some designs' extracted candidate
        # signal names don't survive Yosys flattening literally
        # (renamed/optimized away), so DFG-side role classification and
        # golden-baseline masking both miss real positives that Stage 4's
        # combined_labels.json already found via PyVerilog AST taint (raw
        # pre-synthesis Verilog, unaffected by this).
        # Deliberately AST_ONLY_HIGH specifically, NOT AGREE_HIGH/DFG_ONLY_HIGH
        # — those are satisfied by the legitimate `key`/`state` SOURCE signal
        # itself (role_bonus=1.0 makes both its DFG and AST scores maximal by
        # design), which is not a trojan. AST_ONLY_HIGH requires DFG to be
        # low specifically, which a genuine source signal never is — a first
        # version of this fix used the broader set and mislabeled 35% of
        # AES-T2100 as trojan by counting `key`/`state` themselves.
        # Even AST_ONLY_HIGH alone is too loose to trust as a hard label on
        # its own: Stage 4's 0.08 threshold (tuned for interpretation/
        # visualization, not as a training-label source) also catches
        # ordinary signals with no trojan relevance at all — confirmed on
        # AES-T2100, whose AST_ONLY_HIGH set includes `clk`/`rst`/`b0`-`b3`
        # alongside the real `COUNTER`/`Tj_Trig`. Gate on cfg["trojan_patterns"]
        # too (the same substring predicate golden_delta.py's masking already
        # uses) so only signals with actual trojan-pattern evidence are
        # rescued by this fallback, not everything the loose threshold caught.
        is_trojan = _is_trojan_node(node_name, role)
        if not is_trojan and fused.get("is_injected", 0) and float(dsc.get("delta_taint_score", 0)) > 0.05:
            is_trojan = True
        if not is_trojan and fused.get("category") == "AST_ONLY_HIGH" and _is_trojan_pattern(short):
            is_trojan = True
        labels[i] = int(is_trojan)

    # Sanity check: all features in [0, 1]
    assert features.min() >= -1e-6, f"Feature underflow: min={features.min()}"
    assert features.max() <= 1.0 + 1e-6, f"Feature overflow: max={features.max()}"

    # ── Build edge_index ───────────────────────────────────────────────────────
    # Drop edges whose endpoints fall outside [0, N) — a filtered node would
    # otherwise corrupt GNN training with out-of-bounds indices.
    if edges_raw:
        n_raw = len(edges_raw)
        edges_valid = [(s, d) for s, d in edges_raw
                       if 0 <= s < N and 0 <= d < N]
        n_dropped = n_raw - len(edges_valid)
        if n_dropped:
            print(f"[{design_name}] WARNING: dropped {n_dropped}/{n_raw} edges "
                  f"with out-of-range node IDs (N={N})")
        edge_index = (np.array(edges_valid, dtype=np.int64).T
                      if edges_valid else np.zeros((2, 0), dtype=np.int64))
    else:
        edge_index = np.zeros((2, 0), dtype=np.int64)

    # Hard invariant: every edge must reference a valid node.
    if edge_index.size:
        assert edge_index.max() < N, (
            f"edge_index.max()={edge_index.max()} >= N={N}")
        assert edge_index.min() >= 0, (
            f"edge_index.min()={edge_index.min()} < 0")

    # ── Save ───────────────────────────────────────────────────────────────────
    # Graph-level label: 1 if any node is trojan (TjIn runs normally), 0 for a
    # TjFree run where no node matches _is_trojan_node — used for Stage 6
    # graph-level clean-vs-trojan classification (global_mean_pool head).
    graph_label = np.array([1 if int(labels.sum()) > 0 else 0], dtype=np.int64)

    hw2vec_dir.mkdir(parents=True, exist_ok=True)
    np.save(out_features, features)
    np.save(out_edges, edge_index)
    np.save(out_labels, labels)
    np.save(out_graph_label, graph_label)

    n_trojan_labels = int(labels.sum())
    # A TjIn design with zero trojan-labeled nodes is either a genuine
    # detection miss (empty sources / non-matching trojan_patterns — see
    # taint_diagnostics.json from stage2_ift/dfg_taint.py) or, for non-leakage
    # effect categories, a real result the confidentiality-taint framing
    # simply doesn't apply to. Either way it's silently indistinguishable
    # from a correctly-clean design in labels.npy/graph_label — flag it.
    suspect_mislabeled = variant == "tjin" and n_trojan_labels == 0

    metadata = {
        "design":       design_name,
        "variant":      variant,
        "trojan_type":  cfg.get("trojan_type", "unknown"),
        "n_nodes":      N,
        "n_edges":      edge_index.shape[1],
        "n_trojan":     n_trojan_labels,
        "n_clean":      int((labels == 0).sum()),
        "graph_label":  int(graph_label[0]),
        "suspect_mislabeled": suspect_mislabeled,
        "feature_dim":  14,
        "feature_names": [
            "taint_score", "ast_score", "combined_score",
            "is_on_trojan_path", "timing_sensitive",
            "role_enc_norm", "cell_type_enc", "width_norm",
            "dist_source_norm", "delta_score", "is_injected",
            "glra_dfg_risk", "qtflow_dfg_tls", "qtflow_ast_tls",
        ],
        "node_names": node_names,
    }
    with open(out_meta, "w") as f:
        json.dump(metadata, f, indent=2)

    n_trojan = int(labels.sum())
    print(f"[{design_name}] → hw2vec/: "
          f"features {features.shape} | edges ({edge_index.shape[1]},) | "
          f"labels {N} total, {n_trojan} trojan ({n_trojan/N*100:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Stage 5: GNN-ready export")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--design", metavar="NAME")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--force", action="store_true",
                        help="Recompute even if outputs exist")
    parser.add_argument("--variant", choices=["tjin", "tjfree"], default="tjin")
    args = parser.parse_args()

    designs = discover_designs() if args.all else [args.design]
    errors = []
    for name in designs:
        try:
            export(name, force=args.force, variant=args.variant)
        except Exception as e:
            print(f"[{name}] ERROR: {e}")
            errors.append(name)

    if errors:
        print(f"\nFailed: {errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
