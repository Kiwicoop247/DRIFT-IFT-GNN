"""
stage3_scoring/qtflow_ast.py — QtFlow-style timing-sensitive scoring on AST (Phase 2b)

Source-level complement to qtflow_dfg.py. Walks the PyVerilog AST (via the
shared parse_design helper from stage1_extract.run_ast) and computes a
Timing Leakage Score (TLS) per signal from three syntax-level signals:

    IfStatement.cond     — secret controls WHICH branch runs (pure control flow)
    Cond (ternary ?:)    — same rule at expression level
    Always sensitivity   — secret in sens-list → block re-evaluated on secret

These are exactly the constructs that a Yosys synthesiser may flatten into
bare combinational logic (losing the branching structure), which is why the
AST can see timing channels the DFG cannot.

Golden baseline: re-walk the AST with trojan-named ModuleDefs masked out
(everything declared inside e.g. module TSC is ignored). This mirrors
stage3_scoring.golden_delta.build_masked_graph on the DFG side.

Cycle depth at AST level: count non-blocking substitutions (`<=`) under a
clocked `always` on the source→signal path — each is a register boundary,
so each increments the depth by 1. Blocking `=` assignments are treated as
combinational.

Outputs:
    outputs/{DESIGN}/qtflow_ast_scores.json
        { signal_name: {
              target_cycles, target_cycle_var,
              golden_cycles, cycle_delta,
              timing_tainted_target, timing_tainted_golden,
              ctrl_channels_reached, tls, category
          } ... }

Categories mirror the DFG version:
    TIMING_INJECTED / TIMING_ELEVATED / TIMING_CONTROL /
    TIMING_REDUCED  / TIMING_SAFE

No GHOST category on AST — PyVerilog sees everything the designer wrote,
so the dead-code / ghost problem (Yosys-eliminated signals) doesn't exist
here.

Usage:
    python3 stage3_scoring/qtflow_ast.py --design AES-T2100
    python3 stage3_scoring/qtflow_ast.py --all
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
from stage1_extract.run_ast import (
    parse_design, collect_identifiers_in_subtree, is_clocked_always,
)
from stage1_extract.ast_crossmodule import (
    collect_module_defs, formal_port_names, qualify, qualify_all,
    identify_trojan_modules, is_clock_or_reset, MAX_INSTANCE_DEPTH,
)


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


_is_clock_or_reset = is_clock_or_reset


_collect_module_defs = collect_module_defs
_formal_port_names = formal_port_names
_identify_trojan_modules = identify_trojan_modules


class ASTTimingWalker:
    """Walks a PyVerilog AST and captures everything needed for signal-level
    timing-taint propagation + cycle depth.

    Per-walk state (reset by reset()):
        rhs_deps[lhs]              — {rhs signals} from Assign/Blocking/Nonblocking
        if_branches                — [(cond_sigs, lhs_sigs_in_either_branch)]
        ternary_deps               — [(cond_sigs, result_sigs)]
        sens_ctrl                  — [(sens_sigs, lhs_sigs)] for clocked always
        nb_cycle_lhs               — {signals whose latest write is `<=` under clocked always}
        all_signals                — {every signal name seen}
    """

    def __init__(self, sources: list, trojan_module_names: set,
                 mask_trojan: bool):
        self.sources = set(sources)
        self.trojan_module_names = trojan_module_names
        self.mask_trojan = mask_trojan
        self.reset()

    def reset(self):
        self.rhs_deps: dict[str, set] = defaultdict(set)
        self.if_branches: list[tuple[set, set]] = []
        self.ternary_deps: list[tuple[set, set]] = []
        self.sens_ctrl: list[tuple[set, set]] = []
        self.nb_cycle_lhs: set = set()
        self.all_signals: set = set()
        # Walk state
        self._module_stack: list[str] = []
        self._in_clocked_always: bool = False
        self._always_lhs_stack: list[set] = []   # LHS accumulators per Always
        self._always_sens_stack: list[set] = []  # sens-list accumulators
        # Cross-module instance qualification (see walk_top / _handle_instance).
        self.module_defs: dict = {}
        self._instance_path: list[str] = []
        self._visited_instances: set = set()

    @property
    def _masked(self) -> bool:
        """True if we're currently inside a trojan-named module AND masking
        is on (golden walk)."""
        if not self.mask_trojan:
            return False
        return any(m in self.trojan_module_names for m in self._module_stack)

    def _qualify(self, name: str) -> str:
        return qualify(name, self._instance_path)

    def _qualify_all(self, names) -> set:
        return qualify_all(names, self._instance_path)

    def walk(self, node):
        type_name = type(node).__name__
        entered_module = False
        entered_always = False

        if type_name == "InstanceList":
            callee_name = str(getattr(node, "module", "") or "")
            for inst in (getattr(node, "instances", None) or ()):
                self._handle_instance(inst, callee_name)
            return  # instances are fully handled above; no generic recursion

        if type_name == "ModuleDef" and getattr(node, "name", None):
            self._module_stack.append(str(node.name))
            entered_module = True

        if type_name == "Always":
            clocked = is_clocked_always(node)
            self._always_lhs_stack.append(set())
            self._always_sens_stack.append(set())
            # Grab sens-list signals up-front
            try:
                sl = node.sens_list
                if sl is not None:
                    for sens in sl.children():
                        self._always_sens_stack[-1].update(
                            self._qualify_all(collect_identifiers_in_subtree(sens))
                        )
            except Exception:
                pass
            prev_clocked = self._in_clocked_always
            self._in_clocked_always = clocked
            entered_always = True

        if not self._masked:
            self._record(node, type_name)

        # Recurse
        if hasattr(node, "children"):
            for child in node.children():
                if child is not None and hasattr(child, "children"):
                    self.walk(child)

        # Exit handlers
        if entered_always:
            # Register this always as a sens→lhs control edge (for clocked blocks
            # with data-dependent sensitivity). Only keep if non-empty.
            sens = self._always_sens_stack.pop()
            lhs  = self._always_lhs_stack.pop()
            if self._in_clocked_always and sens and lhs and not self._masked:
                self.sens_ctrl.append((sens, lhs))
            self._in_clocked_always = prev_clocked
        if entered_module:
            self._module_stack.pop()

    def _record(self, node, type_name: str):
        """Capture signal-level structure from the non-masked portion of the AST."""
        if type_name in ("Assign", "BlockingSubstitution",
                         "NonblockingSubstitution"):
            self._record_assignment(node, type_name)
        elif type_name == "IfStatement":
            self._record_if(node)
        elif type_name == "Cond":
            self._record_ternary(node)

    def walk_top(self, module_defs: dict, top_name: str):
        """Entry point: walk only from the design's top module, following
        Instance connections into callee module bodies (see _handle_instance).
        This replaces walking the whole ast_root, which used to visit every
        ModuleDef's body in one shared flat namespace regardless of whether
        it was ever instantiated."""
        self.module_defs = module_defs
        top = module_defs.get(top_name)
        if top is None:
            return
        self.walk(top)

    def _handle_instance(self, inst, callee_name: str):
        """Resolve one module instantiation's port connections and recurse
        into the callee module body under an instance-qualified namespace.

        Fix for the earlier global-namespace blanketing bug (T2600 went from
        0 -> 82/82 INJECTED): every identifier inside the callee's body is
        now qualified by instance path (e.g. 'Trojan.r1', not bare 'r1'), so
        unrelated modules that happen to reuse port names like `key`/`clk`
        no longer collide in rhs_deps. Port connections are recorded as
        bidirectional rhs_deps edges (formal<->actual) since PyVerilog gives
        no reliable direction info for positional port lists in these
        designs (confirmed: every Instance here uses PortArg(portname=None,
        ...), i.e. purely positional) — bidirectional is a safe
        over-approximation for a forward-reachability taint BFS.
        """
        inst_name = str(getattr(inst, "name", "") or "")
        callee_def = self.module_defs.get(callee_name)

        # Golden walk: if the callee module itself is trojan-named, mask the
        # entire instantiation (no wiring, no recursion) — mirrors _masked's
        # module_stack check for non-Instance nodes.
        if self.mask_trojan and callee_name in self.trojan_module_names:
            return

        child_prefix_path = self._instance_path + [inst_name] if inst_name else self._instance_path

        formal_ports = _formal_port_names(callee_def) if callee_def is not None else []
        portlist = getattr(inst, "portlist", None) or ()
        for i, parg in enumerate(portlist):
            portname = getattr(parg, "portname", None)
            actual_node = getattr(parg, "argname", None) if type(parg).__name__ == "PortArg" else parg
            formal = str(portname) if portname else (formal_ports[i] if i < len(formal_ports) else None)
            if formal is None or actual_node is None:
                continue
            qualified_formal = ".".join(child_prefix_path + [formal]) if child_prefix_path else formal
            actual_ids = self._qualify_all(collect_identifiers_in_subtree(actual_node)) \
                if hasattr(actual_node, "children") else set()
            for aid in actual_ids:
                self.rhs_deps[qualified_formal].add(aid)
                self.rhs_deps[aid].add(qualified_formal)
                self.all_signals.add(qualified_formal)
                self.all_signals.add(aid)

        if callee_def is None or not inst_name:
            return
        depth_key = (callee_name, tuple(child_prefix_path))
        if depth_key in self._visited_instances or len(child_prefix_path) > MAX_INSTANCE_DEPTH:
            return
        self._visited_instances.add(depth_key)
        self._instance_path.append(inst_name)
        self.walk(callee_def)
        self._instance_path.pop()

    def _record_assignment(self, node, type_name: str):
        try:
            lhs_node = getattr(node, "left",  None)
            rhs_node = getattr(node, "right", None)
            if lhs_node is None or rhs_node is None:
                return
            lhs_ids = self._qualify_all(collect_identifiers_in_subtree(lhs_node))
            rhs_ids = self._qualify_all(collect_identifiers_in_subtree(rhs_node))
            for lhs in lhs_ids:
                self.rhs_deps[lhs].update(rhs_ids)
                self.all_signals.add(lhs)
            self.all_signals.update(rhs_ids)
            # Track LHS in enclosing Always (for sens-control propagation).
            if self._always_lhs_stack:
                self._always_lhs_stack[-1].update(lhs_ids)
            # Cycle boundary: `<=` under a clocked Always.
            if (type_name == "NonblockingSubstitution"
                    and self._in_clocked_always):
                self.nb_cycle_lhs.update(lhs_ids)
        except Exception:
            pass

    def _record_if(self, node):
        """if (cond) <then> else <else>  →  cond tainted ⇒ every LHS in either
        branch is timing-tainted."""
        try:
            cond = getattr(node, "cond", None)
            if cond is None:
                return
            cond_sigs = self._qualify_all(collect_identifiers_in_subtree(cond))
            branch_lhs: set = set()
            for branch_name in ("true_statement", "false_statement"):
                br = getattr(node, branch_name, None)
                if br is None:
                    continue
                # Collect LHS (left sides of assignments) anywhere under the branch.
                for lhs in _lhs_signals_under(br):
                    branch_lhs.add(self._qualify(lhs))
            if cond_sigs and branch_lhs:
                self.if_branches.append((cond_sigs, branch_lhs))
        except Exception:
            pass

    def _record_ternary(self, node):
        """x = cond ? a : b  →  cond tainted ⇒ x (and every signal in a or b)
        is timing-tainted at the enclosing assignment's LHS.

        PyVerilog's Cond node has .cond, .true_value, .false_value. At walk
        time we don't have the enclosing LHS — so we accumulate cond→rhs
        signals and union into every Assign we've seen whose RHS subtree
        included this Cond's signals. Cheap conservative approximation: the
        result signals are the identifiers inside true_value + false_value,
        and any LHS that depends on those via rhs_deps picks up the taint
        through the downstream propagation step."""
        try:
            cond = getattr(node, "cond", None)
            if cond is None:
                return
            cond_sigs = self._qualify_all(collect_identifiers_in_subtree(cond))
            branch_sigs: set = set()
            for name in ("true_value", "false_value"):
                v = getattr(node, name, None)
                if v is not None:
                    branch_sigs.update(self._qualify_all(collect_identifiers_in_subtree(v)))
            if cond_sigs and branch_sigs:
                self.ternary_deps.append((cond_sigs, branch_sigs))
        except Exception:
            pass


def _lhs_signals_under(node) -> set:
    """Signals that appear on the LHS of any Assign/Blocking/Nonblocking in
    the subtree rooted at `node`. Used for IfStatement branch-effect collection."""
    results: set = set()
    queue = deque([node])
    while queue:
        n = queue.popleft()
        t = type(n).__name__
        if t in ("Assign", "BlockingSubstitution", "NonblockingSubstitution"):
            lhs = getattr(n, "left", None)
            if lhs is not None:
                results.update(collect_identifiers_in_subtree(lhs))
        if hasattr(n, "children"):
            for child in n.children():
                if child is not None and hasattr(child, "children"):
                    queue.append(child)
    return results


def _data_taint_signals(walker: ASTTimingWalker) -> tuple[dict, dict]:
    """Signal-level data-taint propagation. Returns:
        tainted:  {sig → shortest-hops dist_from_source}
        sp_pred:  {sig → one predecessor on the shortest path}  (for ctrl count)

    Two passes (mirrors run_ast.propagate_taint):
      1. BFS forward through rhs_deps (every Assign / Blocking / Nonblocking).
      2. Sens-list reverse propagation — for each clocked always block whose
         LHS set intersects `tainted`, mark the sens-list signals tainted at
         min_lhs_dist + 1. This is how cross-module connections surface:
         Trust-Hub designs pass state/key down through module Instance ports
         that don't appear in rhs_deps, but those signals *do* appear in
         the downstream always block's sens-list (e.g. posedge Tj_Trig).
    Pass 2 is iterated to a fixed point to catch chains of sens→lhs→sens.
    """
    tainted: dict[str, int] = {}
    sp_pred: dict[str, str] = {}
    queue = deque()
    for src in walker.sources:
        tainted[src] = 0
        queue.append(src)

    rhs_to_lhs: dict[str, set] = defaultdict(set)
    for lhs, rhs_set in walker.rhs_deps.items():
        for r in rhs_set:
            rhs_to_lhs[r].add(lhs)

    # Pass 1: rhs_deps BFS
    while queue:
        sig = queue.popleft()
        for lhs in rhs_to_lhs.get(sig, ()):
            if lhs in tainted:
                continue
            tainted[lhs] = tainted[sig] + 1
            sp_pred[lhs] = sig
            queue.append(lhs)

    # Pass 2: sens-list reverse propagation (fixed point). Skip pure
    # clock/reset signals — they appear in every clocked always and would
    # otherwise cascade taint everywhere.
    changed = True
    while changed:
        changed = False
        for sens_sigs, lhs_sigs in walker.sens_ctrl:
            tainted_lhs = [tainted[s] for s in lhs_sigs if s in tainted]
            if not tainted_lhs:
                continue
            base = min(tainted_lhs) + 1
            pred_candidate = next((s for s in lhs_sigs if s in tainted), None)
            for s in sens_sigs:
                if _is_clock_or_reset(s):
                    continue
                if s not in tainted or tainted[s] > base:
                    tainted[s] = base
                    if pred_candidate is not None:
                        sp_pred[s] = pred_candidate
                    changed = True
                    q2 = deque([s])
                    while q2:
                        x = q2.popleft()
                        for lhs in rhs_to_lhs.get(x, ()):
                            nd = tainted[x] + 1
                            if lhs not in tainted or tainted[lhs] > nd:
                                tainted[lhs] = nd
                                sp_pred[lhs] = x
                                changed = True
                                q2.append(lhs)
    return tainted, sp_pred


def _timing_taint_signals(walker: ASTTimingWalker, data_tainted: dict) -> set:
    """Seed timing-taint from IfStatement/Cond/sens-list constructs whose
    condition intersects data-taint. Then propagate forward along rhs_deps.

    Returns the set of signals that are timing-tainted."""
    timing: set = set()

    # Seeds from IfStatement branches
    for cond_sigs, branch_lhs in walker.if_branches:
        if any(c in data_tainted for c in cond_sigs):
            timing.update(branch_lhs)

    # Seeds from ternary conditionals (Cond)
    for cond_sigs, branch_sigs in walker.ternary_deps:
        if any(c in data_tainted for c in cond_sigs):
            timing.update(branch_sigs)

    # Seeds from clocked-always sens-list control. Only fires when a NON-clock
    # sens signal is data-tainted — a tainted clock/reset is noise and would
    # blanket every always block with timing-taint.
    for sens_sigs, lhs_sigs in walker.sens_ctrl:
        tainted_non_clock = [s for s in sens_sigs
                             if s in data_tainted and not _is_clock_or_reset(s)]
        if tainted_non_clock:
            timing.update(lhs_sigs)

    # Propagate forward through rhs_deps — any signal that depends on a
    # timing-tainted signal becomes timing-tainted itself.
    rhs_to_lhs: dict[str, set] = defaultdict(set)
    for lhs, rhs_set in walker.rhs_deps.items():
        for r in rhs_set:
            rhs_to_lhs[r].add(lhs)

    queue = deque(timing)
    while queue:
        sig = queue.popleft()
        for lhs in rhs_to_lhs.get(sig, ()):
            if lhs not in timing:
                timing.add(lhs)
                queue.append(lhs)
    return timing


def _cycle_depth_signals(walker: ASTTimingWalker, sources: list,
                          max_cycles: int) -> tuple[dict, dict]:
    """BFS source→signal tracking (min, max) cycle depth per signal.
    A hop from an `<=`-assigned signal (nb_cycle_lhs) increments depth by 1."""
    rhs_to_lhs: dict[str, set] = defaultdict(set)
    for lhs, rhs_set in walker.rhs_deps.items():
        for r in rhs_set:
            rhs_to_lhs[r].add(lhs)

    cmin: dict[str, int] = {}
    cmax: dict[str, int] = {}
    queue = deque()
    for src in sources:
        cmin[src] = 0
        cmax[src] = 0
        queue.append(src)

    while queue:
        sig = queue.popleft()
        # Crossing an <=-assigned signal is a cycle boundary.
        step = 1 if sig in walker.nb_cycle_lhs else 0
        for lhs in rhs_to_lhs.get(sig, ()):
            new_min = cmin[sig] + step
            new_max = cmax[sig] + step
            if new_max > max_cycles:
                new_max = max_cycles
            changed = False
            if lhs not in cmin or new_min < cmin[lhs]:
                cmin[lhs] = new_min
                changed = True
            if lhs not in cmax or new_max > cmax[lhs]:
                if cmax.get(lhs, -1) < max_cycles:
                    cmax[lhs] = new_max
                    changed = True
            if changed:
                queue.append(lhs)
    return cmin, cmax


def _count_ctrl_channels_ast(walker: ASTTimingWalker, sp_pred: dict,
                              target: str, cap: int) -> int:
    """Walk the sp_pred chain and count how many *control-flow* constructs
    (IfStatement / Cond / clocked sens-list) mention this predecessor as a
    condition signal. Approximation — AST doesn't have a direct cell-on-path
    notion like the DFG does."""
    cond_sigs: set = set()
    for cs, _ in walker.if_branches:
        cond_sigs.update(cs)
    for cs, _ in walker.ternary_deps:
        cond_sigs.update(cs)
    for ss, _ in walker.sens_ctrl:
        cond_sigs.update(ss)

    count = 0
    cur = target
    while cur in sp_pred and count < cap:
        prev = sp_pred[cur]
        if prev in cond_sigs:
            count += 1
        cur = prev
    return count


def compute_qtflow_ast(design_name: str, force: bool = False, variant: str = "tjin") -> dict:
    cfg = get_design_config(design_name, variant=variant)
    output_dir = Path(cfg["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    out_path = output_dir / "qtflow_ast_scores.json"
    if out_path.exists() and not force:
        print(f"[{design_name}] qtflow_ast_scores.json exists — skipping (use --force)")
        with open(out_path) as f:
            return json.load(f)

    sources = cfg["sources"]
    if not sources:
        print(f"[{design_name}] No sources configured — emitting empty scores")
        with open(out_path, "w") as f:
            json.dump({}, f, indent=2)
        return {}

    trojan_modules = _identify_trojan_modules(cfg["trojan_patterns"])

    print(f"[{design_name}] Parsing AST for QtFlow-AST ...")
    ast_root, _ = parse_design(cfg)
    module_defs = _collect_module_defs(ast_root)
    top_name = cfg.get("top_module")
    if not top_name or top_name not in module_defs:
        top_name = next(iter(module_defs), None)

    W_TT   = QTFLOW["W_TIMING_TAINT"]
    W_PX   = QTFLOW["W_PROX"]
    W_CC   = QTFLOW["W_CTRL_COUNT"]
    W_DC   = QTFLOW["W_CYC_DELTA"]
    CAP    = QTFLOW["CTRL_SATURATION"]
    SIM    = QTFLOW["CYCLE_SIM_THRESH"]
    MAX_C  = QTFLOW["MAX_CYCLES"]

    # ── Target walk (trojan modules INCLUDED) ────────────────────────────────
    tgt_walker = ASTTimingWalker(sources, trojan_modules, mask_trojan=False)
    tgt_walker.walk_top(module_defs, top_name)
    tgt_data, tgt_sp = _data_taint_signals(tgt_walker)
    tgt_time        = _timing_taint_signals(tgt_walker, tgt_data)
    tgt_cmin, tgt_cmax = _cycle_depth_signals(tgt_walker, sources, MAX_C)

    # ── Golden walk (trojan modules MASKED) ──────────────────────────────────
    gold_walker = ASTTimingWalker(sources, trojan_modules, mask_trojan=True)
    gold_walker.walk_top(module_defs, top_name)
    gold_data, _gold_sp = _data_taint_signals(gold_walker)
    gold_time          = _timing_taint_signals(gold_walker, gold_data)
    gold_cmin, _gold_cmax = _cycle_depth_signals(gold_walker, sources, MAX_C)

    # ── Score every signal seen in either walk ──────────────────────────────
    all_signals = tgt_walker.all_signals | gold_walker.all_signals
    # Restrict to signals that are either data- or timing-reachable somewhere.
    scorable = {s for s in all_signals
                if s in tgt_data or s in gold_data
                or s in tgt_time or s in gold_time}

    scores: dict = {}
    n_inj = n_elev = n_ctrl = n_red = n_safe = 0

    for sig in scorable:
        tt_tgt = sig in tgt_time
        tt_gld = sig in gold_time
        c_tgt  = tgt_cmin.get(sig)
        c_gld  = gold_cmin.get(sig)
        cv_tgt = (tgt_cmax.get(sig, 0) - tgt_cmin.get(sig, 0)
                  if sig in tgt_cmin else 0)

        prox = 1.0 / (1.0 + c_tgt) if c_tgt is not None else 0.0

        if c_tgt is not None:
            ctrl_n = _count_ctrl_channels_ast(tgt_walker, tgt_sp, sig, CAP)
        else:
            ctrl_n = 0
        ctrl = min(ctrl_n / float(CAP), 1.0)

        if c_tgt is not None and c_gld is not None:
            cycle_delta = c_gld - c_tgt
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

    print(f"[{design_name}] QtFlow-AST: {len(scores)} signals | "
          f"INJECTED={n_inj} ELEVATED={n_elev} CONTROL={n_ctrl} "
          f"REDUCED={n_red} SAFE={n_safe}")
    return scores


def main():
    parser = argparse.ArgumentParser(
        description="Stage 3 / QtFlow-AST: source-level timing-sensitive scoring"
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
            compute_qtflow_ast(name, force=args.force)
        except Exception as e:
            import traceback
            print(f"[{name}] ERROR: {e}")
            traceback.print_exc()
            errors.append(name)
    if errors:
        print(f"\nFailed: {errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
