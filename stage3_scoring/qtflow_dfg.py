"""
stage3_scoring/qtflow_dfg.py — QtFlow-style timing-sensitive scoring (Phase 2)

Computes a Timing Leakage Score (TLS) per signal by propagating a *timing
taint* that is distinct from data taint. Timing taint is emitted only when
data taint reaches a gating/control input of a control-flow cell:

    $mux, $pmux       — tainted select (S) → timing-tainted output
    $memrd_v2 etc.    — tainted address   (ADDR) → timing-tainted output
    $dlatch           — tainted enable    (EN) → timing-tainted output
    $eq/$ne/$lt/..    — any tainted input → timing-tainted output (branch cond)

Once emitted, timing taint propagates forward using the standard cell-rule
from golden_delta.cell_taint_rule_golden (same BFS as data taint, different
seed set).

Orthogonal to GLRA (Phase 1):
    GLRA   asks "did the trojan make the leakage *path* cheaper (TC ratio)?"
    QtFlow asks "did the trojan introduce or tighten a *timing* channel
                (new control-flow edge, fewer cycles, more ctrl cells)?"

Scoring per signal:
    prox       = 1 / (1 + cycle_depth_min_target)        [0 if unreached]
    ctrl       = min(ctrl_channels_reached / 5.0, 1.0)
    delta_cyc  = clamp01((c_golden - c_target) / max(c_golden, 1))
    tls        = clamp01(
                    W_TIMING_TAINT * tt_tgt +
                    W_PROX         * prox   +
                    W_CTRL_COUNT   * ctrl   +
                    W_CYC_DELTA    * delta_cyc )

Categories (aligned with GLRA naming):
    TIMING_INJECTED   — tt_tgt and not tt_gld (new control channel)
    TIMING_ELEVATED   — both tainted, c_tgt < c_gld − CYCLE_SIM_THRESH
    TIMING_CONTROL    — both tainted, |c_tgt − c_gld| ≤ CYCLE_SIM_THRESH
    TIMING_REDUCED    — tt_gld and not tt_tgt (rare; trojan suppressed)
    TIMING_GHOST      — signal is in cfg["ghost_tainted"] (power, not timing;
                        flagged for orthogonality study, tls = GHOST_TLS)
    TIMING_SAFE       — no timing taint anywhere

Output:
    outputs/{DESIGN}/qtflow_dfg_scores.json

Usage:
    python3 stage3_scoring/qtflow_dfg.py --design AES-T2500
    python3 stage3_scoring/qtflow_dfg.py --all
"""

import sys
import json
import argparse
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import (
    get_design_config, discover_designs, QTFLOW,
)
from stage3_scoring.golden_delta import (
    build_masked_graph, cell_taint_rule_golden,
)


_TIMING_CTRL = set(QTFLOW["TIMING_CTRL_CELLS"])
_CYCLE_CELLS = set(QTFLOW["CYCLE_BOUNDARY_CELLS"])
_GATING_PORT = dict(QTFLOW["GATING_PORT"])


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _cell_type_matches(cell_type: str, patterns: set) -> bool:
    """Lower-case substring match: '$mux' matches '$mux', '$muxgate', etc."""
    c = cell_type.lower()
    return any(p in c for p in patterns)


def _cell_type_key(cell_type: str, patterns: set) -> str | None:
    """Return the specific pattern that matched (e.g. '$mux'), else None."""
    c = cell_type.lower()
    for p in patterns:
        if p in c:
            return p
    return None


def _build_full_graph_with_ports(cfg: dict, netlist: dict) -> dict:
    """Target (un-masked) DFG builder. Same shape as golden_delta.build_masked_graph
    but also records per-cell `port_nets[cell][port] -> set(nets)` so we can
    distinguish mux-select vs mux-data, memrd-addr vs memrd-data."""
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
    port_nets: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))

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
                port_nets[cell_name][port].add(net)
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
        "port_nets": port_nets,
    }


def _bfs_data_taint(graph: dict, sources: list) -> tuple[set, dict, dict]:
    """BFS forward from sources with cell-rule propagation. Returns
    (tainted_set, dist_from_source, sp_pred) — same triple as GLRA."""
    node_meta   = graph["node_meta"]
    succ        = graph["succ"]
    pred        = graph["pred"]
    cell_inputs = graph["cell_inputs"]

    tainted: set = set()
    dist: dict = {}
    sp_pred: dict = {}

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


def _emits_timing_taint(cell_name: str, cell_type: str,
                        port_nets: dict, cell_inputs: dict,
                        data_tainted: set) -> bool:
    """Does this cell turn data-taint into timing-taint (on its outputs)?

    For cells in GATING_PORT: only a tainted gating port counts (mux-select,
    memrd-addr, dlatch-en). Data on non-gating ports is NOT a timing channel.

    For comparators ($eq, $ne, $lt, $gt, $le, $ge): any tainted input is a
    branch-timing leak.

    Any other cell type: no timing emission (falls back to data propagation).
    """
    key = _cell_type_key(cell_type, _TIMING_CTRL)
    if key is None:
        return False
    if key in _GATING_PORT:
        port = _GATING_PORT[key]
        gating_nets = port_nets.get(cell_name, {}).get(port, set())
        return any(n in data_tainted for n in gating_nets)
    # Comparator-style — any input tainted
    return any(i in data_tainted for i in cell_inputs.get(cell_name, set()))


def _bfs_timing_taint(graph: dict, data_tainted: set) -> set:
    """Seed timing-tainted set with outputs of cells that emit timing taint,
    then forward-propagate via the standard cell rule."""
    node_meta    = graph["node_meta"]
    succ         = graph["succ"]
    pred         = graph["pred"]
    cell_inputs  = graph["cell_inputs"]
    cell_outputs = graph["cell_outputs"]
    port_nets    = graph["port_nets"]

    seed_cells: list[str] = []
    for name, meta in node_meta.items():
        if meta.get("kind") != "cell":
            continue
        if _emits_timing_taint(name, meta.get("cell_type", ""),
                               port_nets, cell_inputs, data_tainted):
            seed_cells.append(name)

    timing_tainted: set = set()
    queue = deque()
    for cell in seed_cells:
        timing_tainted.add(cell)
        queue.append(cell)
        for out_net in cell_outputs.get(cell, set()):
            if out_net not in timing_tainted:
                timing_tainted.add(out_net)
                queue.append(out_net)

    while queue:
        node = queue.popleft()
        for s in succ[node]:
            if s in timing_tainted:
                continue
            meta = node_meta.get(s, {})
            if meta.get("kind") == "cell":
                should = cell_taint_rule_golden(
                    s, meta.get("cell_type", ""), timing_tainted, cell_inputs
                )
            else:
                should = any(p in timing_tainted for p in pred[s])
            if should:
                timing_tainted.add(s)
                queue.append(s)
    return timing_tainted


def _bfs_cycle_depth(graph: dict, sources: list,
                     max_cycles: int) -> tuple[dict, dict]:
    """BFS tracking (min, max) cycle depth per node. A hop out of a cell whose
    type ∈ CYCLE_BOUNDARY_CELLS increments cycle by 1; combinational hops are
    free. Bounded by `max_cycles` — DFF feedback loops would otherwise cause
    `cmax` to grow forever. Once a node's cmax ≥ max_cycles it is frozen.

    Returns (cycles_min, cycles_max) keyed by node name."""
    node_meta = graph["node_meta"]
    succ      = graph["succ"]

    cmin: dict[str, int] = {}
    cmax: dict[str, int] = {}
    queue = deque()
    for src in sources:
        if src in node_meta:
            cmin[src] = 0
            cmax[src] = 0
            queue.append(src)

    while queue:
        node = queue.popleft()
        meta = node_meta.get(node, {})
        is_boundary = (meta.get("kind") == "cell"
                       and _cell_type_matches(meta.get("cell_type", ""),
                                              _CYCLE_CELLS))
        step = 1 if is_boundary else 0
        for s in succ[node]:
            new_min = cmin[node] + step
            new_max = cmax[node] + step
            if new_max > max_cycles:
                new_max = max_cycles
            changed = False
            if s not in cmin or new_min < cmin[s]:
                cmin[s] = new_min
                changed = True
            if s not in cmax or new_max > cmax[s]:
                # Only re-queue if we haven't already hit the ceiling — prevents
                # unbounded revisits across DFF feedback paths.
                if cmax.get(s, -1) < max_cycles:
                    cmax[s] = new_max
                    changed = True
            if changed:
                queue.append(s)
    return cmin, cmax


def _count_ctrl_channels(graph: dict, sp_pred: dict, target: str,
                         cap: int) -> int:
    """Count control-flow cells along the BFS-shortest source→target path."""
    node_meta = graph["node_meta"]
    count = 0
    cur = target
    while cur in sp_pred:
        prev = sp_pred[cur]
        meta = node_meta.get(prev, {})
        if (meta.get("kind") == "cell"
                and _cell_type_matches(meta.get("cell_type", ""), _TIMING_CTRL)):
            count += 1
            if count >= cap:
                break
        cur = prev
    return count


def compute_qtflow_dfg(design_name: str, force: bool = False, variant: str = "tjin") -> dict:
    cfg = get_design_config(design_name, variant=variant)
    output_dir = Path(cfg["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    out_path = output_dir / "qtflow_dfg_scores.json"
    if out_path.exists() and not force:
        print(f"[{design_name}] qtflow_dfg_scores.json exists — skipping (use --force)")
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

    W_TT   = QTFLOW["W_TIMING_TAINT"]
    W_PX   = QTFLOW["W_PROX"]
    W_CC   = QTFLOW["W_CTRL_COUNT"]
    W_DC   = QTFLOW["W_CYC_DELTA"]
    CAP    = QTFLOW["CTRL_SATURATION"]
    SIM    = QTFLOW["CYCLE_SIM_THRESH"]
    GHOST  = QTFLOW["GHOST_TLS"]
    MAX_C  = QTFLOW["MAX_CYCLES"]
    ghosts = set(cfg.get("ghost_tainted", []))

    # ── Target graph ──────────────────────────────────────────────────────────
    tgt_graph = _build_full_graph_with_ports(cfg, netlist)
    tgt_data, _tgt_dist, tgt_sp = _bfs_data_taint(tgt_graph, sources)
    tgt_time = _bfs_timing_taint(tgt_graph, tgt_data)
    tgt_cmin, tgt_cmax = _bfs_cycle_depth(tgt_graph, sources, MAX_C)

    # ── Golden (masked) graph ─────────────────────────────────────────────────
    gold_graph = build_masked_graph(cfg, netlist)
    # build_masked_graph doesn't emit port_nets; recompute for the mask.
    # Cheapest path: rebuild a port_nets view by re-walking the same cells
    # that survived masking. This mirrors the duplication in glra_dfg.py.
    gold_port_nets: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    top_module = cfg["top_module"]
    module = netlist["modules"][top_module]
    # Reconstruct bit→name using surviving node_meta keys (identical lookup
    # table as in _build_full_graph_with_ports, but filtered to non-masked).
    surviving_nets = {n for n, m in gold_graph["node_meta"].items()
                      if m.get("kind") == "net"}
    bit_to_name = {}
    for net_name, info in module["netnames"].items():
        if net_name not in surviving_nets:
            continue
        for bit in info.get("bits", []):
            if isinstance(bit, int):
                bit_to_name[bit] = net_name
    for cell_name, cell_data in module["cells"].items():
        if cell_name not in gold_graph["node_meta"]:
            continue
        for port, bits in cell_data.get("connections", {}).items():
            for bit in bits:
                if not isinstance(bit, int):
                    continue
                net = bit_to_name.get(bit)
                if net is None:
                    continue
                gold_port_nets[cell_name][port].add(net)
    gold_graph["port_nets"] = gold_port_nets

    gold_data, _gold_dist, gold_sp = _bfs_data_taint(gold_graph, sources)
    gold_time = _bfs_timing_taint(gold_graph, gold_data)
    gold_cmin, _gold_cmax = _bfs_cycle_depth(gold_graph, sources, MAX_C)

    # ── Score every signal reached by data-taint in either graph ──────────────
    all_signals = {s for s in (tgt_data | gold_data | tgt_time | gold_time)
                   if tgt_graph["node_meta"].get(s, {}).get("kind") == "net"
                   or gold_graph["node_meta"].get(s, {}).get("kind") == "net"}
    # Include ghosts even if they're not data-reachable.
    for g in ghosts:
        if g in tgt_graph["node_meta"]:
            all_signals.add(g)

    scores: dict = {}
    n_inj = n_elev = n_ctrl = n_red = n_safe = n_ghost = 0

    for sig in all_signals:
        if sig in ghosts:
            scores[sig] = {
                "target_cycles":         None,
                "target_cycle_var":      0,
                "golden_cycles":         None,
                "cycle_delta":           None,
                "timing_tainted_target": True,
                "timing_tainted_golden": False,
                "ctrl_channels_reached": 0,
                "tls":                   GHOST,
                "category":              "TIMING_GHOST",
            }
            n_ghost += 1
            continue

        tt_tgt = sig in tgt_time
        tt_gld = sig in gold_time
        c_tgt  = tgt_cmin.get(sig)   # may be None
        c_gld  = gold_cmin.get(sig)
        cv_tgt = (tgt_cmax.get(sig, 0) - tgt_cmin.get(sig, 0)
                  if sig in tgt_cmin else 0)

        prox = 1.0 / (1.0 + c_tgt) if c_tgt is not None else 0.0

        if c_tgt is not None:
            ctrl_n = _count_ctrl_channels(tgt_graph, tgt_sp, sig, CAP)
        else:
            ctrl_n = 0
        ctrl = min(ctrl_n / float(CAP), 1.0)

        if c_tgt is not None and c_gld is not None:
            cycle_delta = c_gld - c_tgt      # positive = target earlier
        else:
            cycle_delta = None
        if cycle_delta is not None and c_gld:
            delta_cyc = _clamp01(cycle_delta / max(c_gld, 1))
        else:
            delta_cyc = 1.0 if (tt_tgt and not tt_gld) else 0.0

        tls = _clamp01(
            W_TT * (1.0 if tt_tgt else 0.0) +
            W_PX * prox +
            W_CC * ctrl +
            W_DC * delta_cyc
        )

        # Categorise
        if tt_tgt and not tt_gld:
            category = "TIMING_INJECTED"; n_inj += 1
        elif tt_tgt and tt_gld:
            if (c_tgt is not None and c_gld is not None
                    and c_tgt < c_gld - SIM):
                category = "TIMING_ELEVATED"; n_elev += 1
            else:
                category = "TIMING_CONTROL"; n_ctrl += 1
        elif tt_gld and not tt_tgt:
            category = "TIMING_REDUCED"; n_red += 1
        else:
            category = "TIMING_SAFE"; n_safe += 1

        scores[sig] = {
            "target_cycles":         c_tgt,
            "target_cycle_var":      int(cv_tgt),
            "golden_cycles":         c_gld,
            "cycle_delta":           cycle_delta,
            "timing_tainted_target": bool(tt_tgt),
            "timing_tainted_golden": bool(tt_gld),
            "ctrl_channels_reached": int(ctrl_n),
            "tls":                   round(tls, 4),
            "category":              category,
        }

    with open(out_path, "w") as f:
        json.dump(scores, f, indent=2)

    print(f"[{design_name}] QtFlow-DFG: {len(scores)} signals | "
          f"INJECTED={n_inj} ELEVATED={n_elev} CONTROL={n_ctrl} "
          f"REDUCED={n_red} GHOST={n_ghost} SAFE={n_safe}")
    return scores


def main():
    parser = argparse.ArgumentParser(
        description="Stage 3 / QtFlow-DFG: timing-sensitive leakage scoring"
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
            compute_qtflow_dfg(name, force=args.force)
        except Exception as e:
            print(f"[{name}] ERROR: {e}")
            errors.append(name)
    if errors:
        print(f"\nFailed: {errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
