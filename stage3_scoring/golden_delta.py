"""
stage3_scoring/golden_delta.py — Golden baseline + delta scoring (Stage 3)

Generates a "golden" (trojan-free) taint map by rerunning BFS on the SAME
TjIn netlist with all trojan cells and nets masked out.  The delta between
the full taint_scores.json and the golden scores reveals exactly where the
Trojan perturbs information flow.

Why mask instead of synthesize TjFree?
  Using the identical netlist ensures node IDs align perfectly, giving a
  clean per-node delta.  Synthesizing TjFree would produce a different cell
  graph, making cross-run node matching ambiguous.

Outputs per design:
  outputs/{DESIGN}/golden_scores.json   — per-node golden taint (no trojan)
  outputs/{DESIGN}/golden_nodes.csv     — GNN-ready node feature table
  outputs/{DESIGN}/delta_scores.json    — per-node delta (full − golden)
  outputs/{DESIGN}/golden_report.txt

Usage:
    python3 stage3_scoring/golden_delta.py --design AES-T2100
    python3 stage3_scoring/golden_delta.py --all
"""

import sys
import json
import csv
import argparse
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import (
    get_design_config, discover_designs, SCORING
)

ROLE_ENC = {
    "source": 5, "sink": 4, "trojan_intermediate": 3,
    "key_intermediate": 2, "logic": 1, "internal": 0,
}

KEY_PATTERNS = [
    "k0a", "k0b", "k1a", "k1b", "k2a", "k2b", "k3a", "k3b",
    ".v0", ".v1", ".v2", ".v3",
]


def classify_golden(name: str, sources: list, golden_sinks: list) -> str:
    """Role classification without trojan — only source/sink/key/internal."""
    if name in sources:
        return "source"
    if name in golden_sinks:
        return "sink"
    if any(p in name for p in KEY_PATTERNS):
        return "key_intermediate"
    return "internal"


def cell_taint_rule_golden(cell_name: str, cell_type: str,
                           tainted_set: set, cell_inputs: dict) -> bool:
    inputs = cell_inputs[cell_name]
    tainted_in = [i for i in inputs if i in tainted_set]
    if not tainted_in:
        return False
    c = cell_type.lower()
    if any(k in c for k in ["$xor", "$xnor", "$or", "$not", "inv", "$add", "$sub"]):
        return True
    if "$and" in c:
        return len(tainted_in) == len(inputs)
    if "$mux" in c:
        return True
    if any(k in c for k in ["$dff", "$adff", "$aldff", "$sdff"]):
        d_in = [i for i in inputs if "CLK" not in str(i).upper()]
        return any(i in tainted_set for i in d_in)
    if "$dlatch" in c:
        return True
    if "$mem" in c:
        return True
    if any(k in c for k in ["$eq", "$ne", "$lt", "$gt", "$le", "$ge"]):
        return True
    return len(tainted_in) > 0


TROJAN_PREFIXES = ("Trojan.", "$flatten\\Trojan.",
                   "Trigger.", "$flatten\\Trigger.")


def _make_trojan_predicate(trojan_patterns: list):
    """Return a callable `is_trojan_node(name) -> bool` closed over patterns."""
    def is_trojan_node(name: str) -> bool:
        if any(name.startswith(p) for p in TROJAN_PREFIXES):
            return True
        return any(p in name for p in trojan_patterns if len(p) > 3)
    return is_trojan_node


def build_masked_graph(cfg: dict, netlist: dict):
    """Build the golden (trojan-masked) DFG graph.

    Reusable by downstream scorers (e.g. GLRA) that need to walk the same
    masked graph without re-running taint propagation. Returns a dict with:
      node_meta    — {name: {role, width, cell_type, kind}}
      succ / pred  — adjacency (defaultdict(set))
      cell_inputs  — {cell_name: set(net_names)}
      cell_outputs — {cell_name: set(net_names)}
      sources      — list of source signal names from cfg
      golden_sinks — list of non-trojan output sinks
      excluded     — count of trojan nodes masked out
    """
    top_module = cfg["top_module"]
    module   = netlist["modules"][top_module]
    cells    = module["cells"]
    netnames = module["netnames"]
    ports    = module["ports"]

    sources       = cfg["sources"]
    all_sinks     = cfg["all_sinks"]
    trojan_sinks  = cfg["trojan_sinks"]
    trojan_patterns = cfg["trojan_patterns"]

    # Golden sinks = legitimate outputs only, not trojan outputs
    golden_sinks = [s for s in all_sinks if s not in trojan_sinks] or all_sinks

    is_trojan_node = _make_trojan_predicate(trojan_patterns)

    # bit-ID → net-name lookup
    bit_to_name = {}
    for net_name, info in netnames.items():
        for bit in info.get("bits", []):
            if isinstance(bit, int):
                bit_to_name[bit] = net_name

    node_meta: dict    = {}
    succ               = defaultdict(set)
    pred               = defaultdict(set)
    cell_inputs        = defaultdict(set)
    cell_outputs       = defaultdict(set)
    excluded           = 0

    for net_name, info in netnames.items():
        if is_trojan_node(net_name):
            excluded += 1
            continue
        node_meta[net_name] = {
            "role":      classify_golden(net_name, sources, golden_sinks),
            "width":     len(info.get("bits", [])),
            "cell_type": "net", "kind": "net",
        }
    for port_name, port_info in ports.items():
        if port_name not in node_meta and not is_trojan_node(port_name):
            node_meta[port_name] = {
                "role":      classify_golden(port_name, sources, golden_sinks),
                "width":     len(port_info.get("bits", [])),
                "cell_type": "port", "kind": "net",
            }
    for cell_name, cell_data in cells.items():
        if is_trojan_node(cell_name):
            excluded += 1
            continue
        node_meta[cell_name] = {
            "role": "logic", "width": 1,
            "cell_type": cell_data.get("type", "unknown"), "kind": "cell",
        }
        directions = cell_data.get("port_directions", {})
        conns      = cell_data.get("connections", {})
        for port, bits in conns.items():
            direction = directions.get(port, "input")
            seen = set()
            for bit in bits:
                if not isinstance(bit, int):
                    continue
                net = bit_to_name.get(bit)
                if net is None or net in seen or is_trojan_node(net):
                    continue
                seen.add(net)
                if net not in node_meta:
                    node_meta[net] = {
                        "role": "internal", "width": 1,
                        "cell_type": "net", "kind": "net",
                    }
                if direction == "input":
                    succ[net].add(cell_name)
                    pred[cell_name].add(net)
                    cell_inputs[cell_name].add(net)
                else:
                    succ[cell_name].add(net)
                    pred[net].add(cell_name)
                    cell_outputs[cell_name].add(net)

    return {
        "node_meta":    node_meta,
        "succ":         succ,
        "pred":         pred,
        "cell_inputs":  cell_inputs,
        "cell_outputs": cell_outputs,
        "sources":      sources,
        "golden_sinks": golden_sinks,
        "excluded":     excluded,
    }


def run_golden_delta(design_name: str, force: bool = False, variant: str = "tjin") -> dict:
    cfg = get_design_config(design_name, variant=variant)
    output_dir = Path(cfg["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    out_golden  = output_dir / "golden_scores.json"
    out_delta   = output_dir / "delta_scores.json"
    if out_golden.exists() and not force:
        print(f"[{design_name}] golden_scores.json exists — skipping (use --force)")
        with open(out_golden) as f:
            return json.load(f)

    netlist_path = output_dir / "netlist.json"
    if not netlist_path.exists():
        raise FileNotFoundError(
            f"netlist.json not found for {design_name}. "
            "Run stage1_extract/run_yosys.py first."
        )
    taint_path = output_dir / "taint_scores.json"
    if not taint_path.exists():
        raise FileNotFoundError(
            f"taint_scores.json not found for {design_name}. "
            "Run stage2_ift/dfg_taint.py first."
        )

    print(f"[{design_name}] Loading netlist for golden baseline ...")
    with open(netlist_path) as f:
        netlist = json.load(f)
    with open(taint_path) as f:
        full_scores = json.load(f)

    graph = build_masked_graph(cfg, netlist)
    node_meta    = graph["node_meta"]
    succ         = graph["succ"]
    pred         = graph["pred"]
    cell_inputs  = graph["cell_inputs"]
    sources      = graph["sources"]
    golden_sinks = graph["golden_sinks"]
    excluded     = graph["excluded"]

    all_nodes = set(node_meta.keys())
    print(f"[{design_name}] Golden graph: {len(all_nodes)} nodes "
          f"({excluded} trojan nodes excluded)")

    # ── BFS taint (golden) ────────────────────────────────────────────────────
    tainted = set()
    queue   = deque()
    for src in sources:
        if src in node_meta:
            tainted.add(src)
            queue.append(src)

    while queue:
        node = queue.popleft()
        for s in succ[node]:
            if s in tainted:
                continue
            meta = node_meta.get(s, {})
            if meta.get("kind") == "cell":
                should = cell_taint_rule_golden(
                    s, meta.get("cell_type", ""), tainted, cell_inputs
                )
            else:
                should = any(p in tainted for p in pred[s])
            if should:
                tainted.add(s)
                queue.append(s)

    sinks_reached = [s for s in golden_sinks if s in tainted]
    print(f"[{design_name}] Golden tainted: {len(tainted)}/{len(all_nodes)} | "
          f"Sinks reached: {sinks_reached}")

    # ── QFlow scoring (golden) ────────────────────────────────────────────────
    W_PATH    = SCORING["W_PATH"]
    W_FANOUT  = SCORING["W_FANOUT"]
    W_WIDTH   = SCORING["W_WIDTH"]
    W_ROLE    = SCORING["W_ROLE"]
    MAX_FANOUT = SCORING["MAX_FANOUT"]
    ROLE_BONUS = SCORING["ROLE_BONUS"]

    dist_from_source = {}
    bfs_q = deque()
    for src in sources:
        if src in tainted:
            dist_from_source[src] = 0
            bfs_q.append(src)
    while bfs_q:
        node = bfs_q.popleft()
        for s in succ[node]:
            if s in tainted and s not in dist_from_source:
                dist_from_source[s] = dist_from_source[node] + 1
                bfs_q.append(s)

    dist_to_any_sink = {}
    rev_q = deque()
    for snk in golden_sinks:
        if snk in tainted:
            dist_to_any_sink[snk] = 0
            rev_q.append(snk)
    while rev_q:
        node = rev_q.popleft()
        for p in pred[node]:
            if p in tainted and p not in dist_to_any_sink:
                dist_to_any_sink[p] = dist_to_any_sink[node] + 1
                rev_q.append(p)

    max_dist = max(dist_from_source.values(), default=1)

    golden_scores = {}
    for node in all_nodes:
        meta = node_meta[node]
        role = meta["role"]
        if node not in tainted:
            golden_scores[node] = {
                "taint_binary": 0, "taint_score": 0.0,
                "path_score": 0.0, "fanout_score": 0.0,
                "width_score": 0.0, "role_bonus": 0.0,
                "dist_source": -1, "dist_sink": -1,
            }
            continue

        d_src    = dist_from_source.get(node, max_dist)
        path_s   = 1.0 / (1.0 + d_src)
        fanout_s = min(len(succ[node]) / MAX_FANOUT, 1.0)
        width_s  = min(meta.get("width", 1) / 128.0, 1.0)
        role_b   = ROLE_BONUS.get(role, 0.0)
        final    = min(W_PATH * path_s + W_FANOUT * fanout_s +
                       W_WIDTH * width_s + W_ROLE * role_b, 1.0)

        golden_scores[node] = {
            "taint_binary": 1, "taint_score": round(final, 4),
            "path_score":   round(path_s, 4), "fanout_score": round(fanout_s, 4),
            "width_score":  round(width_s, 4), "role_bonus":   round(role_b, 4),
            "dist_source":  d_src, "dist_sink": dist_to_any_sink.get(node, -1),
        }

    # ── Compute delta: full_scores − golden_scores ────────────────────────────
    delta_scores = {}
    full_only = []   # nodes present in full but not golden (pure trojan nodes)
    for node, full_sc in full_scores.items():
        golden_sc = golden_scores.get(node)
        if golden_sc is None:
            # Trojan-only node (excluded from golden graph)
            delta_scores[node] = {
                "delta_taint_score": round(full_sc["taint_score"], 4),
                "delta_binary": full_sc["taint_binary"],
                "full_score":   full_sc["taint_score"],
                "golden_score": None,
                "is_trojan_only": True,
            }
            full_only.append(node)
        else:
            delta = full_sc["taint_score"] - golden_sc["taint_score"]
            delta_scores[node] = {
                "delta_taint_score": round(delta, 4),
                "delta_binary": int(full_sc["taint_binary"] != golden_sc["taint_binary"]),
                "full_score":   full_sc["taint_score"],
                "golden_score": golden_sc["taint_score"],
                "is_trojan_only": False,
            }

    high_delta = sorted(
        [(n, d["delta_taint_score"]) for n, d in delta_scores.items()
         if abs(d["delta_taint_score"]) > 0.05],
        key=lambda x: abs(x[1]), reverse=True
    )
    print(f"[{design_name}] Delta: {len(full_only)} trojan-only nodes, "
          f"{len(high_delta)} high-delta nodes (|Δ|>0.05)")

    # ── Save outputs ──────────────────────────────────────────────────────────
    # golden_scores.json
    golden_output = {}
    for node, sc in golden_scores.items():
        meta = node_meta[node]
        golden_output[node] = {
            "role": meta["role"], "kind": meta["kind"],
            "cell_type": meta["cell_type"], "width": meta["width"],
            **sc,
        }
    with open(out_golden, "w") as f:
        json.dump(golden_output, f, indent=2)

    # delta_scores.json
    with open(out_delta, "w") as f:
        json.dump(delta_scores, f, indent=2)

    # golden_nodes.csv
    out_nodes = output_dir / "golden_nodes.csv"
    with open(out_nodes, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["node_id", "node_name", "role", "role_enc", "kind",
                    "cell_type", "width", "taint_binary", "taint_score",
                    "path_score", "fanout_score", "width_score",
                    "dist_source", "dist_sink"])
        for i, (node, sc) in enumerate(golden_scores.items()):
            meta = node_meta[node]
            role = meta["role"]
            w.writerow([
                i, node, role, ROLE_ENC.get(role, 0),
                meta["kind"], meta["cell_type"], meta["width"],
                sc["taint_binary"], sc["taint_score"],
                sc["path_score"], sc["fanout_score"], sc["width_score"],
                sc["dist_source"], sc["dist_sink"],
            ])

    # Report
    ts = [s["taint_score"] for s in golden_scores.values() if s["taint_binary"]]
    report_lines = [
        f"GOLDEN BASELINE REPORT — {design_name}", "=" * 60,
        f"Netlist          : {netlist_path}",
        f"Total nodes      : {len(all_nodes)} (golden, excl. {excluded} trojan)",
        f"Tainted          : {len(tainted)}  ({len(tainted)/len(all_nodes)*100:.1f}%)",
        f"Score range      : {min(ts, default=0):.3f} – {max(ts, default=0):.3f}",
        "", "SINK COVERAGE", "-" * 40,
    ]
    for snk in golden_sinks:
        d = dist_from_source.get(snk, -1)
        report_lines.append(f"  {snk:<40} reached={snk in tainted}  dist={d}")

    report_lines += ["", "TOP DELTA NODES (|Δ|>0.05)", "-" * 40]
    for node, delta in high_delta[:20]:
        full_s  = delta_scores[node]["full_score"]
        golden_s = delta_scores[node]["golden_score"]
        trojan_tag = " [TROJAN-ONLY]" if delta_scores[node]["is_trojan_only"] else ""
        report_lines.append(
            f"  {node:<55} Δ={delta:+.3f}  "
            f"full={full_s:.3f}  golden={golden_s if golden_s is not None else 'N/A'}"
            f"{trojan_tag}"
        )

    out_report = output_dir / "golden_report.txt"
    with open(out_report, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"[{design_name}] → {out_golden.name} | {out_delta.name} | "
          f"{out_nodes.name} | {out_report.name}")

    return golden_output


def main():
    parser = argparse.ArgumentParser(
        description="Stage 3: Golden baseline + delta scoring"
    )
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
            run_golden_delta(name, force=args.force)
        except Exception as e:
            print(f"[{name}] ERROR: {e}")
            errors.append(name)

    if errors:
        print(f"\nFailed: {errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
