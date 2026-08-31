"""
stage2_ift/dfg_taint.py — Generalized DFG taint propagation (Stage 2)

Loads a Yosys-synthesized netlist.json (from stage1_extract/run_yosys.py),
performs binary BFS taint propagation with cell-type-aware rules, then
applies QFlow quantitative scoring. Config is loaded from pipeline_config.py
(auto-discovered + designs.json overrides) — no hardcoded signal names.

Outputs per design:
  outputs/{DESIGN}/taint_scores.json  — per-node IFT labels and scores
  outputs/{DESIGN}/dfg_nodes.csv      — GNN-ready node feature table
  outputs/{DESIGN}/dfg_edges.csv      — GNN-ready edge list
  outputs/{DESIGN}/dfg_taint_report.txt

Usage:
    python3 stage2_ift/dfg_taint.py --design AES-T2100
    python3 stage2_ift/dfg_taint.py --design AES-T2300 --fsm --tc-model
    python3 stage2_ift/dfg_taint.py --all
"""

import sys
import json
import csv
import argparse
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import (
    get_design_config, discover_designs, get_output_path, SCORING, TC_WEIGHTS
)

# ---------------------------------------------------------------------------
# Role classification
# ---------------------------------------------------------------------------

ROLE_ENC = {
    "source": 5, "sink": 4, "trojan_intermediate": 3,
    "key_intermediate": 2, "logic": 1, "internal": 0,
}

KEY_PATTERNS = [
    "k0a", "k0b", "k1a", "k1b", "k2a", "k2b", "k3a", "k3b",
    ".v0", ".v1", ".v2", ".v3",
]


def classify_node(name: str, sources: list, all_sinks: list,
                  trojan_patterns: list) -> str:
    if name in sources:
        return "source"
    if name in all_sinks:
        return "sink"
    if any(p in name for p in trojan_patterns):
        return "trojan_intermediate"
    if any(p in name for p in KEY_PATTERNS):
        return "key_intermediate"
    return "internal"


# ---------------------------------------------------------------------------
# Cell-type taint rule — UNCHANGED from step3_taint_fixed.py
# ---------------------------------------------------------------------------

def cell_taint_rule(cell_name: str, cell_type: str, tainted_set: set,
                    cell_inputs: dict) -> bool:
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
        return True    # select tainted = timing leak
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


# ---------------------------------------------------------------------------
# Transmission Cost per cell (GLRA model) — used with --tc-model
# ---------------------------------------------------------------------------

def get_tc_weight(cell_type: str) -> float:
    c = cell_type.lower()
    for pattern, weight in TC_WEIGHTS.items():
        if pattern == "default":
            continue
        if pattern in c:
            return weight
    return TC_WEIGHTS["default"]


# ---------------------------------------------------------------------------
# FSM detection — used with --fsm flag
# ---------------------------------------------------------------------------

def detect_fsm_regs(cells: dict, cell_inputs: dict, cell_outputs: dict,
                    succ: dict, pred: dict) -> set:
    """
    Find DFF cells whose Q output feeds back (through combinational logic)
    to their own D input. These are FSM state registers.
    Returns a set of cell names identified as FSM state registers.
    """
    dff_cells = {
        name for name, data in cells.items()
        if any(k in data.get("type", "").lower()
               for k in ["$dff", "$adff", "$aldff", "$sdff"])
    }

    fsm_regs = set()
    for dff in dff_cells:
        # Q outputs of this DFF
        q_outs = cell_outputs.get(dff, set())
        # Do any of those net outputs eventually reach a D input of the SAME DFF?
        # Simple reachability check: BFS from Q outputs, stop if we reach dff's D inputs
        d_ins = cell_inputs.get(dff, set())
        visited = set()
        queue = deque(q_outs)
        found_feedback = False
        while queue and not found_feedback:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            if node in d_ins:
                found_feedback = True
                break
            for s in succ.get(node, set()):
                if s not in visited:
                    queue.append(s)
        if found_feedback:
            fsm_regs.add(dff)

    return fsm_regs


# ---------------------------------------------------------------------------
# Main pipeline function
# ---------------------------------------------------------------------------

def run_dfg_taint(design_name: str, use_tc_model: bool = False,
                  detect_fsm: bool = False, force: bool = False,
                  variant: str = "tjin") -> dict:
    """
    Run DFG taint analysis for a single design.
    Returns the scores dict (node -> score info).
    """
    cfg = get_design_config(design_name, variant=variant)
    output_dir = Path(cfg["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    netlist_path = output_dir / "netlist.json"
    if not netlist_path.exists():
        raise FileNotFoundError(
            f"netlist.json not found for {design_name}. "
            f"Run stage1_extract/run_yosys.py first."
        )

    out_scores = output_dir / "taint_scores.json"
    if out_scores.exists() and not force:
        print(f"[{design_name}] taint_scores.json exists — skipping (use --force)")
        with open(out_scores) as f:
            return json.load(f)

    print(f"[{design_name}] Loading netlist ...")
    with open(netlist_path) as f:
        netlist = json.load(f)

    # Find the target module
    top_module = cfg["top_module"]
    if top_module not in netlist["modules"]:
        available = list(netlist["modules"].keys())
        raise KeyError(
            f"Module '{top_module}' not in netlist. Available: {available}"
        )
    module   = netlist["modules"][top_module]
    cells    = module["cells"]
    netnames = module["netnames"]
    ports    = module["ports"]

    # Config-driven signal lists
    sources         = cfg["sources"]
    all_sinks       = cfg["all_sinks"]
    trojan_patterns = cfg["trojan_patterns"]
    ghost_tainted   = cfg.get("ghost_tainted", [])
    # trojan_sinks: resolve hierarchical names — Yosys flattening prefixes
    # the instance name, so "trigger" (from TSC_and.v output port) becomes
    # "Trojan.trigger" in the flat netlist. Expand to match both forms.
    _raw_trojan_sinks = cfg["trojan_sinks"]
    trojan_sinks = list(_raw_trojan_sinks)  # start with original names

    # Validate configured sources exist
    for src in sources:
        if src not in netnames and src not in ports:
            print(f"  [WARN] Source '{src}' not found in netlist for {design_name}")

    # No sources → the BFS below never seeds, so every node silently ends up
    # taint_score=0.000 with no error. That's correct behavior for a design
    # with no confidentiality-leakage source (see designs.json/trojan_categories.json
    # for non-leakage designs), but indistinguishable downstream from a design
    # that genuinely has no leakage — flag it explicitly so Stage 4/pilot
    # tooling can tell "no sources configured" apart from "sources configured,
    # correctly found nothing".
    if not sources:
        print(f"  [WARN] No sources configured for {design_name} — taint scores will be all-zero.")

    # ── Build bit-ID → net-name lookup ──────────────────────────────────────
    bit_to_name = {}
    for net_name, info in netnames.items():
        for bit in info.get("bits", []):
            if isinstance(bit, int):
                bit_to_name[bit] = net_name

    # ── Build graph ──────────────────────────────────────────────────────────
    node_meta    = {}
    succ         = defaultdict(set)
    pred         = defaultdict(set)
    cell_inputs  = defaultdict(set)
    cell_outputs = defaultdict(set)

    for net_name, info in netnames.items():
        node_meta[net_name] = {
            "role":      classify_node(net_name, sources, all_sinks, trojan_patterns),
            "width":     len(info.get("bits", [])),
            "cell_type": "net",
            "kind":      "net",
        }
    for port_name, port_info in ports.items():
        if port_name not in node_meta:
            node_meta[port_name] = {
                "role":      classify_node(port_name, sources, all_sinks, trojan_patterns),
                "width":     len(port_info.get("bits", [])),
                "cell_type": "port",
                "kind":      "net",
            }
    for cell_name, cell_data in cells.items():
        node_meta[cell_name] = {
            "role":      "logic",
            "width":     1,
            "cell_type": cell_data.get("type", "unknown"),
            "kind":      "cell",
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
                if net is None or net in seen:
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

    all_nodes = set(node_meta.keys())
    print(f"[{design_name}] Graph: {len(all_nodes)} nodes, {len(cells)} cells, "
          f"{len(netnames)} nets")

    # Resolve hierarchical trojan sink names.
    # After Yosys flatten, "trigger" becomes "Trojan.trigger" (or "inst.trigger").
    # Also add the top-level port that the trojan feeds (e.g. Tj_Trig).
    for raw in _raw_trojan_sinks:
        for node in all_nodes:
            if node == raw:
                continue  # already in list
            # Match hierarchical suffix: "Module.trigger" ends with ".trigger"
            if node.endswith(f".{raw}") and node not in trojan_sinks:
                trojan_sinks.append(node)
    if len(trojan_sinks) > len(_raw_trojan_sinks):
        extras = [s for s in trojan_sinks if s not in _raw_trojan_sinks]
        print(f"[{design_name}] Trojan sinks (resolved): {trojan_sinks} "
              f"(+{len(extras)} hierarchical)")

    # ── Optional FSM detection ───────────────────────────────────────────────
    fsm_regs = set()
    if detect_fsm:
        fsm_regs = detect_fsm_regs(cells, cell_inputs, cell_outputs, succ, pred)
        print(f"[{design_name}] FSM state registers: {len(fsm_regs)}")
        for reg in sorted(fsm_regs):
            print(f"    {reg}")

    # ── Binary BFS taint propagation ────────────────────────────────────────
    print(f"[{design_name}] Binary taint propagation ...")
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
                should_taint = cell_taint_rule(
                    s, meta.get("cell_type", ""), tainted, cell_inputs
                )
            else:
                should_taint = any(p in tainted for p in pred[s])
            if should_taint:
                tainted.add(s)
                queue.append(s)

    # Mark configured ghost nodes as tainted
    ghost_added = []
    for ghost in ghost_tainted:
        if ghost in node_meta and ghost not in tainted:
            tainted.add(ghost)
            ghost_added.append(ghost)

    sinks_reached = [s for s in all_sinks if s in tainted]
    print(f"[{design_name}] Tainted: {len(tainted)}/{len(all_nodes)} | "
          f"Ghost added: {len(ghost_added)} | Sinks reached: {sinks_reached}")

    # ── QFlow scoring ────────────────────────────────────────────────────────
    W_PATH   = SCORING["W_PATH"]
    W_FANOUT = SCORING["W_FANOUT"]
    W_WIDTH  = SCORING["W_WIDTH"]
    W_ROLE   = SCORING["W_ROLE"]
    MAX_FANOUT = SCORING["MAX_FANOUT"]
    ROLE_BONUS = SCORING["ROLE_BONUS"]

    # Forward BFS — distance from source
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

    # Ghost nodes: assign distance based on SECRETKey if available
    ghost_ref_dist = dist_from_source.get(
        next((n for n in node_meta if "SECRETKey" in n), None), 3
    )
    for ghost in ghost_tainted:
        if ghost in tainted and ghost not in dist_from_source:
            dist_from_source[ghost] = ghost_ref_dist + 1

    # Reverse BFS from trojan sinks only — is_on_trojan_path
    dist_to_trojan_sink = {}
    rev_q = deque()
    for snk in trojan_sinks:
        if snk in tainted:
            dist_to_trojan_sink[snk] = 0
            rev_q.append(snk)
    while rev_q:
        node = rev_q.popleft()
        for p in pred[node]:
            if p in tainted and p not in dist_to_trojan_sink:
                dist_to_trojan_sink[p] = dist_to_trojan_sink[node] + 1
                rev_q.append(p)
    # Ghost trojan sinks
    for ghost in ghost_tainted:
        if ghost in tainted and ghost not in dist_to_trojan_sink:
            dist_to_trojan_sink[ghost] = 1

    # Reverse BFS from all sinks — dist_to_any_sink
    dist_to_any_sink = {}
    rev_q2 = deque()
    for snk in all_sinks:
        if snk in tainted:
            dist_to_any_sink[snk] = 0
            rev_q2.append(snk)
    while rev_q2:
        node = rev_q2.popleft()
        for p in pred[node]:
            if p in tainted and p not in dist_to_any_sink:
                dist_to_any_sink[p] = dist_to_any_sink[node] + 1
                rev_q2.append(p)

    max_dist = max(dist_from_source.values(), default=1)

    # TC model: average TC weight on shortest path from source to this node
    # (only computed when --tc-model is on)
    def avg_path_tc(node: str) -> float:
        if not use_tc_model:
            return 0.0
        path_cells = []
        cur = node
        visited = set()
        while cur not in sources and cur not in visited:
            visited.add(cur)
            parents = [p for p in pred.get(cur, set())
                       if p in tainted and dist_from_source.get(p, 9999) < dist_from_source.get(cur, 0)]
            if not parents:
                break
            best_parent = min(parents, key=lambda p: dist_from_source.get(p, 9999))
            if node_meta.get(best_parent, {}).get("kind") == "cell":
                path_cells.append(get_tc_weight(node_meta[best_parent]["cell_type"]))
            cur = best_parent
        return sum(path_cells) / len(path_cells) if path_cells else 0.0

    scores = {}
    for node in all_nodes:
        meta = node_meta[node]
        role = meta["role"]

        if node not in tainted:
            scores[node] = {
                "taint_binary": 0, "taint_score": 0.0,
                "path_score": 0.0, "fanout_score": 0.0,
                "width_score": 0.0, "role_bonus": 0.0,
                "dist_source": -1, "dist_sink": -1,
                "is_on_trojan_path": 0,
                "is_fsm_state_reg": 1 if node in fsm_regs else 0,
            }
            continue

        d_src    = dist_from_source.get(node, max_dist)
        path_s   = 1.0 / (1.0 + d_src)
        fanout_s = min(len(succ[node]) / MAX_FANOUT, 1.0)
        width_s  = min(meta.get("width", 1) / 128.0, 1.0)
        role_b   = ROLE_BONUS.get(role, 0.0)

        if use_tc_model:
            tc = avg_path_tc(node)
            path_s = path_s * (1.0 - tc)

        on_trojan = 1 if (node in dist_from_source and
                          node in dist_to_trojan_sink) else 0

        final = min(
            W_PATH * path_s + W_FANOUT * fanout_s +
            W_WIDTH * width_s + W_ROLE * role_b,
            1.0,
        )

        scores[node] = {
            "taint_binary": 1,
            "taint_score":  round(final, 4),
            "path_score":   round(path_s, 4),
            "fanout_score": round(fanout_s, 4),
            "width_score":  round(width_s, 4),
            "role_bonus":   round(role_b, 4),
            "dist_source":  d_src,
            "dist_sink":    dist_to_any_sink.get(node, -1),
            "is_on_trojan_path": on_trojan,
            "is_fsm_state_reg":  1 if node in fsm_regs else 0,
        }

    # ── Save outputs ──────────────────────────────────────────────────────────
    # taint_scores.json
    output_json = {}
    for node, sc in scores.items():
        meta = node_meta[node]
        output_json[node] = {
            "role": meta["role"], "kind": meta["kind"],
            "cell_type": meta["cell_type"], "width": meta["width"],
            **sc,
        }
    with open(out_scores, "w") as f:
        json.dump(output_json, f, indent=2)

    # Diagnostics sidecar — kept separate from taint_scores.json (whose keys
    # are consumed downstream as node names) so this flag can't be mistaken
    # for a node. See the "no sources configured" warning above.
    n_tainted = sum(1 for sc in scores.values() if sc.get("taint_binary"))
    with open(output_dir / "taint_diagnostics.json", "w") as f:
        json.dump({
            "sources_empty": not bool(sources),
            "sources": sources,
            "n_tainted_nodes": n_tainted,
            "n_total_nodes": len(scores),
            "all_zero_taint": n_tainted == 0,
        }, f, indent=2)

    # dfg_nodes.csv
    out_nodes = output_dir / "dfg_nodes.csv"
    with open(out_nodes, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["node_id", "node_name", "role", "role_enc", "kind",
                    "cell_type", "width", "taint_binary", "taint_score",
                    "path_score", "fanout_score", "width_score",
                    "dist_source", "dist_sink", "is_on_trojan_path",
                    "is_fsm_state_reg"])
        for i, (node, sc) in enumerate(scores.items()):
            meta = node_meta[node]
            role = meta["role"]
            w.writerow([
                i, node, role, ROLE_ENC.get(role, 0),
                meta["kind"], meta["cell_type"], meta["width"],
                sc["taint_binary"], sc["taint_score"],
                sc["path_score"], sc["fanout_score"], sc["width_score"],
                sc["dist_source"], sc["dist_sink"],
                sc["is_on_trojan_path"], sc["is_fsm_state_reg"],
            ])

    # dfg_edges.csv
    out_edges = output_dir / "dfg_edges.csv"
    node_to_id = {n: i for i, n in enumerate(scores.keys())}
    edge_count = 0
    with open(out_edges, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src_id", "dst_id", "src_name", "dst_name",
                    "src_tainted", "dst_tainted", "both_on_trojan"])
        for src_node, successors in succ.items():
            if src_node not in node_to_id:
                continue
            for dst_node in successors:
                if dst_node not in node_to_id:
                    continue
                both = (scores[src_node]["is_on_trojan_path"] and
                        scores[dst_node]["is_on_trojan_path"])
                w.writerow([
                    node_to_id[src_node], node_to_id[dst_node],
                    src_node, dst_node,
                    scores[src_node]["taint_binary"],
                    scores[dst_node]["taint_binary"],
                    int(both),
                ])
                edge_count += 1

    # Report
    tainted_scores   = [s["taint_score"] for s in scores.values() if s["taint_binary"]]
    on_trojan_count  = sum(1 for s in scores.values() if s["is_on_trojan_path"])
    by_role          = defaultdict(list)
    for node, sc in scores.items():
        if sc["taint_binary"]:
            by_role[node_meta[node]["role"]].append(sc["taint_score"])

    report_lines = [
        f"DFG TAINT REPORT — {design_name}", "=" * 60,
        f"Netlist          : {netlist_path}",
        f"Total nodes      : {len(all_nodes)}",
        f"Tainted          : {len(tainted)}  ({len(tainted)/len(all_nodes)*100:.1f}%)",
        f"Ghost nodes added: {len(ghost_added)}",
        f"On Trojan path   : {on_trojan_count}",
        f"FSM regs         : {len(fsm_regs)}",
        f"Score range      : {min(tainted_scores, default=0):.3f} – "
        f"{max(tainted_scores, default=0):.3f}",
        "", "SINK COVERAGE", "-" * 40,
    ]
    for snk in all_sinks:
        d = dist_from_source.get(snk, -1)
        report_lines.append(
            f"  {snk:<40} reached={snk in tainted}  dist={d}"
        )
    report_lines += ["", "SCORE BY ROLE", "-" * 40]
    for role, sc_list in sorted(by_role.items()):
        avg = sum(sc_list) / len(sc_list)
        report_lines.append(
            f"  {role:<25} n={len(sc_list):<5} avg={avg:.3f} max={max(sc_list):.3f}"
        )
    report_lines += ["", "TROJAN PATH NODES", "-" * 40]
    tp = [(n, s) for n, s in scores.items() if s["is_on_trojan_path"]]
    tp.sort(key=lambda x: x[1]["dist_source"])
    for node, sc in tp:
        report_lines.append(
            f"  {node:<55} score={sc['taint_score']:.3f} "
            f"d_src={sc['dist_source']}"
        )

    out_report = output_dir / "dfg_taint_report.txt"
    with open(out_report, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"[{design_name}] → {out_scores.name} | {out_nodes.name} "
          f"({len(scores)} nodes) | {out_edges.name} ({edge_count} edges) | "
          f"{out_report.name}")

    return output_json


def main():
    parser = argparse.ArgumentParser(description="Stage 2: DFG taint propagation")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--design", metavar="NAME")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--tc-model", action="store_true",
                        help="Use GLRA Transmission Cost scoring instead of QFlow proxy")
    parser.add_argument("--fsm", action="store_true",
                        help="Detect FSM state registers ($dff feedback loops)")
    parser.add_argument("--force", action="store_true",
                        help="Recompute even if outputs exist")
    args = parser.parse_args()

    designs = discover_designs() if args.all else [args.design]
    errors = []
    for name in designs:
        try:
            run_dfg_taint(name,
                          use_tc_model=args.tc_model,
                          detect_fsm=args.fsm,
                          force=args.force)
        except Exception as e:
            print(f"[{name}] ERROR: {e}")
            errors.append(name)

    if errors:
        print(f"\nFailed: {errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
