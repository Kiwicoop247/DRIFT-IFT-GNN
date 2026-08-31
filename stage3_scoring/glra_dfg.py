"""
stage3_scoring/glra_dfg.py — Graph-based Leakage Risk Assessment (Phase 1)

Computes a normalised leakage-risk score per signal on the gate-level DFG by
comparing cumulative Transmission Cost (TC) along source → signal paths in
the TARGET (trojan-inserted) netlist vs the GOLDEN (trojan-masked) netlist.

Convention used in this module:
    TC_weight ∈ (0, 1]  — "cost / hardness to pass"  (XOR ≈ 0.1, AND ≈ 0.8)
    tc_sum(path)         = Σ TC_weight  over cells on the path from source
    target_sum, golden_sum are those sums on their respective graphs.
    leak_ratio           = golden_sum / target_sum
                           > 1  → target path is cheaper → leakier
                           ≈ 1  → unchanged
                           < 1  → target path is more expensive → safer
    risk_score           = clamp01(0.5 + 0.5 * (leak_ratio − 1.0))
                           0.0 → strongly safer than golden
                           0.5 → no perturbation
                           1.0 → strongly leakier than golden (Trojan effect)

Corner cases (handled explicitly):
    - signal not tainted in target      → risk_score = 0.0
    - signal not tainted in golden only → risk_score = 1.0  (NEW leakage path
      introduced by the trojan — the classic "injected" case)
    - both untainted                    → skip (absent from output)
    - target_sum == 0                   → leak_ratio = +∞ → risk_score = 1.0

Outputs:
    outputs/{DESIGN}/glra_dfg_scores.json
        { signal_name: {
              "target_tc":   float | null,
              "golden_tc":   float | null,
              "leak_ratio":  float | null,
              "risk_score":  float (0..1),
              "category":    "INJECTED" | "ELEVATED" | "NO_CHANGE" |
                             "REDUCED"  | "TARGET_ONLY" | "GOLDEN_ONLY",
          } ... }

Usage:
    python3 stage3_scoring/glra_dfg.py --design AES-T2100
    python3 stage3_scoring/glra_dfg.py --all
"""

import sys
import json
import argparse
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import (
    get_design_config, discover_designs, TC_WEIGHTS,
)
from stage3_scoring.golden_delta import (
    build_masked_graph, cell_taint_rule_golden, _make_trojan_predicate,
)


def _tc_weight(cell_type: str) -> float:
    """Return TC weight for a Yosys cell type (falls back to 'default')."""
    c = cell_type.lower()
    for pattern, weight in TC_WEIGHTS.items():
        if pattern == "default":
            continue
        if pattern in c:
            return weight
    return TC_WEIGHTS["default"]


def _build_full_graph(cfg: dict, netlist: dict) -> dict:
    """Build the target (un-masked) DFG graph. Same structure as
    `build_masked_graph` but keeps trojan cells/nets."""
    top_module = cfg["top_module"]
    module = netlist["modules"][top_module]
    cells, netnames, ports = module["cells"], module["netnames"], module["ports"]

    bit_to_name = {}
    for net_name, info in netnames.items():
        for bit in info.get("bits", []):
            if isinstance(bit, int):
                bit_to_name[bit] = net_name

    node_meta: dict = {}
    succ, pred = defaultdict(set), defaultdict(set)
    cell_inputs, cell_outputs = defaultdict(set), defaultdict(set)

    for net_name, info in netnames.items():
        node_meta[net_name] = {
            "role": "internal",
            "width": len(info.get("bits", [])),
            "cell_type": "net", "kind": "net",
        }
    for port_name, port_info in ports.items():
        node_meta.setdefault(port_name, {
            "role": "internal",
            "width": len(port_info.get("bits", [])),
            "cell_type": "port", "kind": "net",
        })
    for cell_name, cell_data in cells.items():
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
                if net is None or net in seen:
                    continue
                seen.add(net)
                node_meta.setdefault(net, {
                    "role": "internal", "width": 1,
                    "cell_type": "net", "kind": "net",
                })
                if direction == "input":
                    succ[net].add(cell_name)
                    pred[cell_name].add(net)
                    cell_inputs[cell_name].add(net)
                else:
                    succ[cell_name].add(net)
                    pred[net].add(cell_name)
                    cell_outputs[cell_name].add(net)

    return {
        "node_meta": node_meta,
        "succ": succ, "pred": pred,
        "cell_inputs": cell_inputs, "cell_outputs": cell_outputs,
    }


def _bfs_taint_and_distance(graph: dict, sources: list):
    """BFS forward from sources. Returns (tainted_set, dist_from_source,
    predecessor_on_shortest_path). The shortest-path predecessor lets us
    reconstruct a source→node path for TC accumulation."""
    node_meta   = graph["node_meta"]
    succ        = graph["succ"]
    pred        = graph["pred"]
    cell_inputs = graph["cell_inputs"]

    tainted: set = set()
    dist: dict   = {}
    sp_pred: dict = {}   # node → one predecessor on a BFS-shortest source→node path

    queue = deque()
    for src in sources:
        if src in node_meta:
            tainted.add(src)
            dist[src] = 0
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
                dist[s] = dist[node] + 1
                sp_pred[s] = node
                queue.append(s)
    return tainted, dist, sp_pred


def _tc_along_path(graph: dict, sp_pred: dict, target: str) -> float:
    """Cumulative TC weight along the BFS-shortest source→target path.

    Walks sp_pred chain backwards summing cell TC weights; net nodes
    contribute nothing (they are transparent wires). Returns 0.0 if target
    isn't in sp_pred (i.e. it IS a source itself)."""
    node_meta = graph["node_meta"]
    total = 0.0
    cur = target
    while cur in sp_pred:
        prev = sp_pred[cur]
        meta = node_meta.get(prev, {})
        if meta.get("kind") == "cell":
            total += _tc_weight(meta.get("cell_type", ""))
        cur = prev
    return total


def compute_glra_dfg(design_name: str, force: bool = False, variant: str = "tjin") -> dict:
    cfg = get_design_config(design_name, variant=variant)
    output_dir = Path(cfg["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    out_path = output_dir / "glra_dfg_scores.json"
    if out_path.exists() and not force:
        print(f"[{design_name}] glra_dfg_scores.json exists — skipping (use --force)")
        with open(out_path) as f:
            return json.load(f)

    netlist_path = output_dir / "netlist.json"
    if not netlist_path.exists():
        raise FileNotFoundError(
            f"netlist.json missing for {design_name} — run stage1 first")

    with open(netlist_path) as f:
        netlist = json.load(f)

    sources = cfg["sources"]
    if not sources:
        print(f"[{design_name}] No sources configured — emitting empty scores")
        with open(out_path, "w") as f:
            json.dump({}, f, indent=2)
        return {}

    # ── Target (full) graph + BFS ──────────────────────────────────────────────
    target_graph = _build_full_graph(cfg, netlist)
    tgt_tainted, tgt_dist, tgt_sp = _bfs_taint_and_distance(target_graph, sources)

    # Honour ghost_tainted — configured signals that Yosys optimised away but
    # still exist conceptually (T2100's LEAK inverter chain). Present only in
    # the target; they are implicitly trojan-introduced.
    ghost_tainted = cfg.get("ghost_tainted", [])
    for ghost in ghost_tainted:
        if ghost in target_graph["node_meta"] and ghost not in tgt_tainted:
            tgt_tainted.add(ghost)
            tgt_dist[ghost] = tgt_dist.get(ghost, 9999)   # very far, zero TC path

    # ── Golden (masked) graph + BFS ────────────────────────────────────────────
    golden_graph = build_masked_graph(cfg, netlist)
    gold_bfs = _bfs_taint_and_distance(golden_graph, sources)
    gold_tainted, gold_sp = gold_bfs[0], gold_bfs[2]

    # ── Score every signal seen in either graph ────────────────────────────────
    all_signals = (tgt_tainted | gold_tainted)
    # Restrict to signals, not cells (cells are implementation detail; reports
    # and fusion operate at the net/signal level).
    all_signals = {
        s for s in all_signals
        if target_graph["node_meta"].get(s, {}).get("kind") == "net"
        or golden_graph["node_meta"].get(s, {}).get("kind") == "net"
    }

    is_trojan = _make_trojan_predicate(cfg["trojan_patterns"])

    scores: dict = {}
    n_injected = n_elevated = n_reduced = n_unchanged = 0

    for sig in all_signals:
        in_target = sig in tgt_tainted
        in_golden = sig in gold_tainted

        tgt_tc = _tc_along_path(target_graph, tgt_sp, sig) if in_target else None
        gold_tc = _tc_along_path(golden_graph, gold_sp, sig) if in_golden else None

        if in_target and in_golden:
            # Both tainted — compare cumulative TC.
            if tgt_tc <= 1e-9:
                leak_ratio = float("inf") if gold_tc > 0 else 1.0
            else:
                leak_ratio = gold_tc / tgt_tc
            if abs(leak_ratio - 1.0) < 0.05:
                category = "NO_CHANGE"
                n_unchanged += 1
            elif leak_ratio > 1.0:
                category = "ELEVATED"   # target leaks more than golden
                n_elevated += 1
            else:
                category = "REDUCED"    # target leaks less (rare)
                n_reduced += 1
        elif in_target and not in_golden:
            # Trojan-injected path — not present in golden at all.
            leak_ratio = float("inf")
            # If this signal is in a trojan module, call it INJECTED explicitly.
            category = "INJECTED" if is_trojan(sig) else "TARGET_ONLY"
            n_injected += 1
        else:  # in_golden but not in_target — rare (trojan suppressed a path)
            leak_ratio = 0.0
            category = "GOLDEN_ONLY"
            n_reduced += 1

        # Map leak_ratio to a bounded [0,1] risk.
        if leak_ratio == float("inf"):
            risk = 1.0
        elif leak_ratio == 0.0:
            risk = 0.0
        else:
            risk = 0.5 + 0.5 * (leak_ratio - 1.0)
            risk = max(0.0, min(1.0, risk))

        scores[sig] = {
            "target_tc":  round(tgt_tc, 4)  if tgt_tc is not None else None,
            "golden_tc":  round(gold_tc, 4) if gold_tc is not None else None,
            "leak_ratio": (None if leak_ratio == float("inf")
                           else round(leak_ratio, 4)),
            "risk_score": round(risk, 4),
            "category":   category,
        }

    with open(out_path, "w") as f:
        json.dump(scores, f, indent=2)

    print(f"[{design_name}] GLRA-DFG: {len(scores)} signals | "
          f"INJECTED={n_injected} ELEVATED={n_elevated} "
          f"REDUCED={n_reduced} NO_CHANGE={n_unchanged}")
    return scores


def main():
    parser = argparse.ArgumentParser(
        description="Stage 3 / GLRA-DFG: normalized leakage-risk scoring"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--design", metavar="NAME")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    designs = discover_designs() if args.all else [args.design]
    errors = []
    for name in designs:
        try:
            compute_glra_dfg(name, force=args.force)
        except Exception as e:
            print(f"[{name}] ERROR: {e}")
            errors.append(name)
    if errors:
        print(f"\nFailed: {errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
