"""
stage1_extract/run_ast.py — PyVerilog AST extraction (Stage 1: AST path)

Parses the TjIn Verilog source files with PyVerilog, walks the resulting
Abstract Syntax Tree, performs name-based taint propagation, and applies
QFlow quantitative scoring. This is the source-level complement to the
Yosys DFG path — it catches dead logic (like T2100's power-side-channel
inverter chain) that Yosys removes during synthesis.

Outputs per design:
  outputs/{DESIGN}/ast_nodes.csv          — GNN-ready AST node feature table
  outputs/{DESIGN}/ast_edges.csv          — parent→child edge list
  outputs/{DESIGN}/ast_taint_scores.json  — per-signal taint scores
  outputs/{DESIGN}/ast_report.txt

Validation target for AES-T2100:
  COUNTER → taint_score ≈ 0.376, role=trojan_intermediate, dist_source=2

Usage:
    python3 stage1_extract/run_ast.py --design AES-T2100
    python3 stage1_extract/run_ast.py --all
"""

import sys
import csv
import json
import argparse
import re
import tempfile
import os
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import pyverilog  # noqa: F401  -- prefer the pip-installed package
except ImportError:
    _vendored_pyverilog = Path(__file__).resolve().parents[3] / "testfiles" / "Pyverilog"
    if _vendored_pyverilog.exists():
        sys.path.insert(0, str(_vendored_pyverilog))

from config.pipeline_config import (
    get_design_config, discover_designs, SCORING
)
from stage1_extract.ast_crossmodule import (
    collect_module_defs, formal_port_names, qualify, qualify_all,
    identify_trojan_modules, is_clock_or_reset, MAX_INSTANCE_DEPTH,
)

# Suppress PyVerilog LALR table generation warning on first run
import warnings
warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# AST node type → integer encoding (for GNN)
# ---------------------------------------------------------------------------

AST_TYPE_ENC = {
    "Source": 0, "Description": 1, "ModuleDef": 2, "Paramlist": 3,
    "Portlist": 4, "Ioport": 5, "Port": 6, "Input": 7, "Output": 8,
    "Inout": 9, "Reg": 10, "Wire": 11, "Integer": 12, "Parameter": 13,
    "Localparam": 14, "Assign": 15, "Always": 16, "SensList": 17,
    "Sens": 18, "Block": 19, "IfStatement": 20, "ForStatement": 21,
    "WhileStatement": 22, "CaseStatement": 23, "Case": 24,
    "BlockingSubstitution": 25, "NonblockingSubstitution": 26,
    "Identifier": 27, "Lvalue": 28, "Rvalue": 29, "Concat": 30,
    "Partselect": 31, "Pointer": 32, "IntConst": 33, "FloatConst": 34,
    "StringConst": 35, "UnaryOperator": 36, "Operator": 37,
    "Plus": 38, "Minus": 39, "Times": 40, "Divide": 41, "Mod": 42,
    "Power": 43, "Xor": 44, "Xnor": 45, "And": 46, "Or": 47,
    "Nand": 48, "Nor": 49, "Not": 50, "Ulnot": 51, "Unot": 52,
    "Uand": 53, "Uor": 54, "Uxor": 55, "Land": 56, "Lor": 57,
    "Eq": 58, "NotEq": 59, "LessEq": 60, "GreaterEq": 61,
    "LessThan": 62, "GreaterThan": 63, "Sll": 64, "Srl": 65,
    "Sla": 66, "Sra": 67, "Cond": 68,
    "Instance": 69, "InstanceList": 70, "ParamArg": 71, "PortArg": 72,
    "Width": 73, "Length": 74, "Dimensions": 75, "RegArray": 76,
    "WireArray": 77, "Decl": 78, "Initial": 79, "Task": 80,
    "Function": 81, "FunctionCall": 82, "SystemCall": 83,
    "EventStatement": 84, "WaitStatement": 85,
    "SingleStatement": 86,
}

ROLE_ENC = {
    "source": 5, "sink": 4, "trojan_intermediate": 3,
    "key_intermediate": 2, "logic": 1, "internal": 0,
}

KEY_PATTERNS = [
    "k0a", "k0b", "k1a", "k1b", "k2a", "k2b", "k3a", "k3b",
    "v0", "v1", "v2", "v3",
]


# ---------------------------------------------------------------------------
# Signal name extraction from PyVerilog AST nodes
# ---------------------------------------------------------------------------

def get_signal_name(node) -> str:
    """Extract the signal/identifier name from an AST node, or ''."""
    try:
        type_name = type(node).__name__
        if type_name in ("Reg", "Wire", "Input", "Output", "Inout",
                         "Integer", "Parameter", "Localparam",
                         "Port", "Identifier"):
            return str(node.name) if node.name else ""
        if type_name == "Instance":
            return str(node.name) if node.name else ""
    except Exception:
        pass
    return ""


def is_clocked_always(always_node) -> bool:
    """Return True if an Always block has posedge/negedge sensitivity."""
    try:
        from pyverilog.vparser.ast import Sens
        sens_list = always_node.sens_list
        if sens_list is None:
            return False
        for child in sens_list.children():
            if hasattr(child, 'type'):
                if str(child.type).lower() in ("posedge", "negedge"):
                    return True
    except Exception:
        pass
    return False


def collect_identifiers_in_subtree(node) -> list:
    """Return all Identifier signal names within a subtree."""
    names = []
    queue = deque([node])
    while queue:
        n = queue.popleft()
        if type(n).__name__ == "Identifier" and n.name:
            names.append(str(n.name))
        if hasattr(n, 'children'):
            queue.extend(n.children())
    return names


# ---------------------------------------------------------------------------
# AST walker — builds flat node table + assignment graph
# ---------------------------------------------------------------------------

class ASTWalker:
    def __init__(self, sources, all_sinks, trojan_patterns, key_patterns=None):
        self.sources         = set(sources)
        self.all_sinks       = set(all_sinks)
        self.trojan_patterns = trojan_patterns
        self.key_patterns    = key_patterns or KEY_PATTERNS

        # Flat node records (one per AST node)
        self.nodes = []           # list of dicts
        self._node_counter = 0

        # Assignment graph: signal → set of signals it depends on (RHS identifiers)
        # Used for taint propagation
        self.rhs_deps: dict[str, set] = defaultdict(set)  # lhs → {rhs, ...}

        # Sensitivity list graph: always block id → (sens_signals, lhs_signals)
        # Used to propagate taint from tainted LHS assignments to sensitivity signals
        self._always_blocks: list[dict] = []   # [{lhs: set, sens: set}]
        self._current_always_idx = -1

        # Current walk state
        self._current_module = ""
        self._in_clocked_always = False
        self._depth = 0

    def classify(self, name: str) -> str:
        if name in self.sources:
            return "source"
        if name in self.all_sinks:
            return "sink"
        if any(p in name for p in self.trojan_patterns):
            return "trojan_intermediate"
        if any(p in name for p in self.key_patterns):
            return "key_intermediate"
        return "internal"

    def _is_timing_sensitive(self, node) -> bool:
        """True for nodes in a clocked always block, or IfStatements whose
        condition references a counter/state-like signal."""
        type_name = type(node).__name__
        if self._in_clocked_always:
            return True
        if type_name == "IfStatement":
            cond_ids = collect_identifiers_in_subtree(node.cond)
            return any(
                "COUNTER" in n.upper() or "STATE" in n.upper()
                for n in cond_ids
            )
        return False

    def _record_node(self, node, parent_id: int) -> int:
        node_id   = self._node_counter
        self._node_counter += 1
        type_name = type(node).__name__
        sig_name  = get_signal_name(node)
        lineno    = getattr(node, 'lineno', -1) or -1

        self.nodes.append({
            "node_id":    node_id,
            "parent_id":  parent_id,
            "ast_type":   type_name,
            "ast_type_enc": AST_TYPE_ENC.get(type_name, 99),
            "signal_name": sig_name,
            "module_name": self._current_module,
            "lineno":     int(lineno),
            "depth":      self._depth,
            "timing_sensitive": 1 if self._is_timing_sensitive(node) else 0,
            # taint fields filled in later
            "taint_binary": 0,
            "taint_score":  0.0,
            "role":         self.classify(sig_name) if sig_name else "internal",
            "role_enc":     ROLE_ENC.get(
                self.classify(sig_name) if sig_name else "internal", 0),
            "is_on_trojan_path": 0,
            "dist_source":  -1,
        })
        return node_id

    def _extract_assignment(self, node):
        """Extract lhs → rhs dependency from Assign/Blocking/NonBlocking nodes."""
        try:
            lhs_node = node.left  if hasattr(node, 'left')  else None
            rhs_node = node.right if hasattr(node, 'right') else None
            if lhs_node is None or rhs_node is None:
                return
            lhs_ids = collect_identifiers_in_subtree(lhs_node)
            rhs_ids = collect_identifiers_in_subtree(rhs_node)
            for lhs in lhs_ids:
                self.rhs_deps[lhs].update(rhs_ids)
            # Track LHS in current always block
            if self._current_always_idx >= 0:
                self._always_blocks[self._current_always_idx]["lhs"].update(lhs_ids)
        except Exception:
            pass

    def _extract_sensitivity_signals(self, always_node) -> set:
        """Return set of signal names appearing in the Always block's sensitivity list."""
        sigs = set()
        try:
            sens_list = always_node.sens_list
            if sens_list is None:
                return sigs
            for sens in sens_list.children():
                ids = collect_identifiers_in_subtree(sens)
                sigs.update(ids)
        except Exception:
            pass
        return sigs

    def walk(self, node, parent_id: int = -1):
        """Recursively walk the AST tree."""
        type_name = type(node).__name__

        # Track module context
        entered_module = False
        prev_module = self._current_module
        if type_name == "ModuleDef" and hasattr(node, 'name') and node.name:
            self._current_module = str(node.name)
            entered_module = True

        # Track always block — record sensitivity signals for later taint propagation
        prev_always_idx = self._current_always_idx
        prev_clocked = self._in_clocked_always
        if type_name == "Always":
            self._in_clocked_always = is_clocked_always(node)
            sens_sigs = self._extract_sensitivity_signals(node)
            self._always_blocks.append({"sens": sens_sigs, "lhs": set()})
            self._current_always_idx = len(self._always_blocks) - 1

        # Record this node
        node_id = self._record_node(node, parent_id)

        # Extract assignment edges for taint propagation
        if type_name in ("Assign", "BlockingSubstitution", "NonblockingSubstitution"):
            self._extract_assignment(node)

        # Walk children
        self._depth += 1
        if hasattr(node, 'children'):
            for child in node.children():
                if child is not None and hasattr(child, 'children'):
                    self.walk(child, node_id)
        self._depth -= 1

        # Restore context
        if entered_module:
            self._current_module = prev_module
        if type_name == "Always":
            self._in_clocked_always = prev_clocked
            self._current_always_idx = prev_always_idx


# ---------------------------------------------------------------------------
# Name-based taint propagation over assignment graph
# ---------------------------------------------------------------------------

def propagate_taint(walker: ASTWalker) -> dict[str, int]:
    """
    BFS taint propagation over the signal assignment graph + sensitivity lists.

    Pass 1 — Assignment BFS: propagate taint through data dependencies
      (e.g. SECRETKey <= key  →  SECRETKey tainted at dist=1)

    Pass 2 — Sensitivity list: for each always block where any LHS is tainted,
      mark the sensitivity signals as tainted at dist = min_lhs_dist + 1.
      This captures timing-side-channel paths where COUNTER controls WHEN
      a secret is captured (e.g. @(posedge COUNTER[127]) in TSC.v).

    Returns {signal_name → dist_from_source}.
    """
    tainted_signals: dict[str, int] = {}
    queue: deque = deque()

    for src in walker.sources:
        tainted_signals[src] = 0
        queue.append(src)

    # Pass 1: BFS through assignment dependencies
    while queue:
        sig = queue.popleft()
        dist = tainted_signals[sig]
        for lhs, deps in walker.rhs_deps.items():
            if lhs in tainted_signals:
                continue
            if sig in deps:
                tainted_signals[lhs] = dist + 1
                queue.append(lhs)

    # Pass 2: sensitivity list propagation
    # For each always block, if any of its LHS signals are tainted,
    # mark all sensitivity signals as tainted at min_lhs_dist + 1
    changed = True
    while changed:
        changed = False
        for block in walker._always_blocks:
            lhs_tainted = [
                tainted_signals[s] for s in block["lhs"]
                if s in tainted_signals
            ]
            if not lhs_tainted:
                continue
            min_lhs_dist = min(lhs_tainted)
            new_dist = min_lhs_dist + 1
            for sens_sig in block["sens"]:
                if sens_sig not in tainted_signals or \
                        tainted_signals[sens_sig] > new_dist:
                    tainted_signals[sens_sig] = new_dist
                    changed = True

    return tainted_signals


# ---------------------------------------------------------------------------
# Cross-module taint graph (instance-qualified)
#
# ASTWalker.walk() above builds one flat, unqualified rhs_deps graph over the
# whole source tree and never extracts Instance port connections — taint
# cannot cross a module boundary (e.g. TSC Trojan(s2[89], s5[121], Tj_Trig)
# never connects s2/s5 to the Trojan module's r1/r2). This mirrors the fix
# already applied to stage3_scoring.qtflow_ast's ASTTimingWalker: walk only
# from the top module, following Instance connections into callee bodies
# under an instance-qualified namespace (e.g. 'r1' -> 'Trojan.r1') so
# unrelated modules reusing port names don't collide.
# ---------------------------------------------------------------------------

class _CrossModuleTaintWalker:
    """Instance-qualified walk that builds rhs_deps + sensitivity-control
    edges for cross-module taint propagation. A cut-down sibling of
    qtflow_ast.ASTTimingWalker — only extracts what propagate_taint needs
    (assignment deps + sens-list control), not the timing/cycle-depth
    structures QtFlow-AST additionally tracks."""

    def __init__(self, trojan_module_names: set):
        self.trojan_module_names = trojan_module_names
        self.rhs_deps: dict[str, set] = defaultdict(set)
        self.sens_ctrl: list[tuple[set, set]] = []
        self.all_signals: set = set()
        # Instance paths (dot-joined) whose callee module is trojan-named —
        # used to mark cross-module trojan signals whose bare port name
        # doesn't itself match trojan_patterns (e.g. 'Trojan.r1').
        self.trojan_instance_paths: set = set()

        self.module_defs: dict = {}
        self._instance_path: list = []
        self._visited_instances: set = set()
        self._always_lhs_stack: list = []
        self._always_sens_stack: list = []
        self._in_clocked_always = False

    def walk_top(self, module_defs: dict, top_name: str):
        self.module_defs = module_defs
        top = module_defs.get(top_name)
        if top is None:
            return
        self.walk(top)

    def walk(self, node):
        type_name = type(node).__name__

        if type_name == "InstanceList":
            callee_name = str(getattr(node, "module", "") or "")
            for inst in (getattr(node, "instances", None) or ()):
                self._handle_instance(inst, callee_name)
            return  # instances are fully handled above; no generic recursion

        entered_always = False
        prev_clocked = self._in_clocked_always
        if type_name == "Always":
            clocked = is_clocked_always(node)
            self._always_lhs_stack.append(set())
            self._always_sens_stack.append(set())
            try:
                sl = node.sens_list
                if sl is not None:
                    for sens in sl.children():
                        self._always_sens_stack[-1].update(
                            qualify_all(collect_identifiers_in_subtree(sens),
                                        self._instance_path)
                        )
            except Exception:
                pass
            self._in_clocked_always = clocked
            entered_always = True

        if type_name in ("Assign", "BlockingSubstitution", "NonblockingSubstitution"):
            self._record_assignment(node)

        if hasattr(node, "children"):
            for child in node.children():
                if child is not None and hasattr(child, "children"):
                    self.walk(child)

        if entered_always:
            sens = self._always_sens_stack.pop()
            lhs = self._always_lhs_stack.pop()
            if self._in_clocked_always and sens and lhs:
                self.sens_ctrl.append((sens, lhs))
            self._in_clocked_always = prev_clocked

    def _record_assignment(self, node):
        try:
            lhs_node = getattr(node, "left", None)
            rhs_node = getattr(node, "right", None)
            if lhs_node is None or rhs_node is None:
                return
            lhs_ids = qualify_all(collect_identifiers_in_subtree(lhs_node), self._instance_path)
            rhs_ids = qualify_all(collect_identifiers_in_subtree(rhs_node), self._instance_path)
            for lhs in lhs_ids:
                self.rhs_deps[lhs].update(rhs_ids)
            self.all_signals.update(lhs_ids)
            self.all_signals.update(rhs_ids)
            if self._always_lhs_stack:
                self._always_lhs_stack[-1].update(lhs_ids)
        except Exception:
            pass

    def _handle_instance(self, inst, callee_name: str):
        """Resolve one module instantiation's port connections and recurse
        into the callee module body under an instance-qualified namespace.
        Port connections are recorded as bidirectional rhs_deps edges
        (formal<->actual) since PyVerilog gives no reliable direction info
        for positional port lists — bidirectional is a safe
        over-approximation for a forward-reachability taint BFS."""
        inst_name = str(getattr(inst, "name", "") or "")
        callee_def = self.module_defs.get(callee_name)

        if callee_name in self.trojan_module_names:
            prefix = ".".join(self._instance_path + [inst_name]) if inst_name else callee_name
            self.trojan_instance_paths.add(prefix)

        child_path = self._instance_path + [inst_name] if inst_name else self._instance_path
        formals = formal_port_names(callee_def) if callee_def is not None else []
        portlist = getattr(inst, "portlist", None) or ()
        for i, parg in enumerate(portlist):
            portname = getattr(parg, "portname", None)
            actual_node = getattr(parg, "argname", None) if type(parg).__name__ == "PortArg" else parg
            formal = str(portname) if portname else (formals[i] if i < len(formals) else None)
            if formal is None or actual_node is None:
                continue
            qualified_formal = ".".join(child_path + [formal]) if child_path else formal
            actual_ids = qualify_all(collect_identifiers_in_subtree(actual_node), self._instance_path) \
                if hasattr(actual_node, "children") else set()
            for aid in actual_ids:
                self.rhs_deps[qualified_formal].add(aid)
                self.rhs_deps[aid].add(qualified_formal)
                self.all_signals.add(qualified_formal)
                self.all_signals.add(aid)

        if callee_def is None or not inst_name:
            return
        depth_key = (callee_name, tuple(child_path))
        if depth_key in self._visited_instances or len(child_path) > MAX_INSTANCE_DEPTH:
            return
        self._visited_instances.add(depth_key)
        self._instance_path.append(inst_name)
        self.walk(callee_def)
        self._instance_path.pop()


def _propagate_taint_qualified(rhs_deps: dict, sens_ctrl: list, sources: set) -> dict[str, int]:
    """Same two-pass BFS as propagate_taint(), over an instance-qualified
    graph. Returns {qualified_signal_name → dist_from_source}."""
    tainted: dict[str, int] = {}
    queue: deque = deque()
    for src in sources:
        tainted[src] = 0
        queue.append(src)

    rhs_to_lhs: dict[str, set] = defaultdict(set)
    for lhs, rset in rhs_deps.items():
        for r in rset:
            rhs_to_lhs[r].add(lhs)

    while queue:
        sig = queue.popleft()
        for lhs in rhs_to_lhs.get(sig, ()):
            if lhs in tainted:
                continue
            tainted[lhs] = tainted[sig] + 1
            queue.append(lhs)

    changed = True
    while changed:
        changed = False
        for sens_sigs, lhs_sigs in sens_ctrl:
            lhs_dists = [tainted[s] for s in lhs_sigs if s in tainted]
            if not lhs_dists:
                continue
            base = min(lhs_dists) + 1
            for s in sens_sigs:
                if s not in tainted or tainted[s] > base:
                    tainted[s] = base
                    changed = True
                    q2 = deque([s])
                    while q2:
                        x = q2.popleft()
                        for lhs in rhs_to_lhs.get(x, ()):
                            nd = tainted[x] + 1
                            if lhs not in tainted or tainted[lhs] > nd:
                                tainted[lhs] = nd
                                changed = True
                                q2.append(lhs)
    return tainted


def build_crossmodule_taint(ast_root, sources: list, trojan_patterns: list,
                             top_name: str | None) -> tuple[dict, set]:
    """Build the instance-qualified taint graph and collapse it to bare
    signal names for use alongside the existing flat-walk node table.

    Returns:
        bare_tainted   — {bare_signal_name → min dist_from_source across all
                          qualified occurrences of that name}
        trojan_signals — bare signal names that are qualified under a
                          trojan-module instance (catches cross-module
                          trojans whose bare port names don't themselves
                          match trojan_patterns, e.g. 'Trojan.r1' -> 'r1')
    """
    module_defs = collect_module_defs(ast_root)
    if not top_name or top_name not in module_defs:
        top_name = next(iter(module_defs), None)
    if top_name is None:
        return {}, set()

    trojan_modules = identify_trojan_modules(trojan_patterns)
    walker = _CrossModuleTaintWalker(trojan_modules)
    walker.walk_top(module_defs, top_name)

    tainted_qualified = _propagate_taint_qualified(
        walker.rhs_deps, walker.sens_ctrl, set(sources))

    bare_tainted: dict[str, int] = {}
    for qname, dist in tainted_qualified.items():
        bare = qname.rsplit(".", 1)[-1]
        if bare not in bare_tainted or dist < bare_tainted[bare]:
            bare_tainted[bare] = dist

    trojan_qualified_signals = {
        q for q in walker.all_signals
        if any(q == p or q.startswith(p + ".") for p in walker.trojan_instance_paths)
    }
    # Exclude clock/reset — a clk/rst wired into the trojan instance's ports
    # is ordinary infrastructure, not a trojan-specific signal (matches the
    # same filter qtflow_ast.py applies for the identical reason).
    trojan_signals = {
        q.rsplit(".", 1)[-1] for q in trojan_qualified_signals
        if not is_clock_or_reset(q.rsplit(".", 1)[-1])
    }

    return bare_tainted, trojan_signals


# ---------------------------------------------------------------------------
# QFlow scoring (same formula as dfg_taint.py)
# ---------------------------------------------------------------------------

def compute_scores(walker: ASTWalker,
                   tainted_signals: dict[str, int],
                   trojan_patterns: list,
                   crossmodule_trojan_signals: set = frozenset()) -> None:
    """Fill in taint_binary, taint_score, dist_source, is_on_trojan_path in walker.nodes."""
    W_PATH   = SCORING["W_PATH"]
    W_FANOUT = SCORING["W_FANOUT"]
    W_WIDTH  = SCORING["W_WIDTH"]
    W_ROLE   = SCORING["W_ROLE"]
    ROLE_BONUS = SCORING["ROLE_BONUS"]

    # Compute fanout per signal name (how many nodes reference it)
    signal_fanout: dict[str, int] = defaultdict(int)
    for node in walker.nodes:
        sig = node["signal_name"]
        if sig:
            signal_fanout[sig] += 1

    max_fanout = max(signal_fanout.values(), default=1)
    max_dist   = max(tainted_signals.values(), default=1)

    # Which signals are on the trojan path (tainted AND classified as trojan,
    # by bare-name pattern match OR by being qualified under a trojan-module
    # instance in the cross-module graph, e.g. 'Trojan.r1' -> 'r1')?
    trojan_signal_names = {
        sig for sig in tainted_signals
        if any(p in sig for p in trojan_patterns)
    } | (crossmodule_trojan_signals & set(tainted_signals))

    for node in walker.nodes:
        sig  = node["signal_name"]
        role = node["role"]

        if not sig or sig not in tainted_signals:
            continue  # leave defaults (0 taint)

        dist     = tainted_signals[sig]
        path_s   = 1.0 / (1.0 + dist)
        fanout   = signal_fanout.get(sig, 1)
        fanout_s = min(fanout / max(max_fanout, 1), 1.0)
        width_s  = 0.1   # AST nodes don't carry width — use small constant
        role_b   = ROLE_BONUS.get(role, 0.0)
        final    = min(W_PATH * path_s + W_FANOUT * fanout_s +
                       W_WIDTH * width_s + W_ROLE * role_b, 1.0)

        node["taint_binary"]      = 1
        node["taint_score"]       = round(final, 4)
        node["dist_source"]       = dist
        node["is_on_trojan_path"] = 1 if sig in trojan_signal_names else 0


# ---------------------------------------------------------------------------
# Main per-design function
# ---------------------------------------------------------------------------

def parse_design(cfg: dict):
    """Parse a design's Verilog source through PyVerilog. Shared by run_ast
    (Stage 1) and stage3_scoring.qtflow_ast (Phase 2b).

    Handles Trust-Hub preprocessing quirks:
      - Broken absolute `include paths from the original author's machine
      - Empty port slots `, ,` (e.g. aes_128.v a10(clk, k9, , k9b))
      - Trailing commas before `)`
      - Spaces inside numeric literals (e.g. 34'b 0011... in wb_conmax-T200)

    Returns (ast_root, verilog_files) where verilog_files is the list of
    original source paths (useful for module→file mapping)."""
    from pyverilog.vparser.parser import parse

    verilog_dir  = Path(cfg["verilog_dir"])
    verilog_files = [str(verilog_dir / f) for f in cfg["verilog_files"]]

    _inc_re = re.compile(r'(`include\s+")([^"]+)(")')

    def _fix_includes(text, src_dir):
        def _fix(m):
            inc_path = Path(m.group(2))
            if inc_path.is_absolute() and not inc_path.exists():
                local = src_dir / inc_path.name
                if local.exists():
                    return m.group(1) + str(local) + m.group(3)
            return m.group(0)
        return _inc_re.sub(_fix, text)

    tmp_files = []
    preprocessed_files = []
    for fpath in verilog_files:
        src_dir = Path(fpath).parent
        content = Path(fpath).read_text(encoding='utf-8', errors='ignore')
        cleaned = _fix_includes(content, src_dir)
        cleaned = re.sub(r',(\s*),', r', _nc_ ,', cleaned)
        cleaned = re.sub(r',(\s*\))', r'\1', cleaned)
        cleaned = re.sub(
            r"(\d+)'([bBoOdDhH])\s+([0-9a-fA-FxXzZ_?]+)",
            r"\1'\2\3", cleaned
        )
        if cleaned != content:
            tmp = tempfile.NamedTemporaryFile(
                mode='w', suffix='.v', delete=False,
                prefix=f"pv_{Path(fpath).stem}_"
            )
            tmp.write(cleaned)
            tmp.close()
            preprocessed_files.append(tmp.name)
            tmp_files.append(tmp.name)
        else:
            preprocessed_files.append(fpath)

    try:
        include_dirs = list({str(Path(f).parent) for f in verilog_files})
        ast_root, _ = parse(preprocessed_files,
                            preprocess_include=include_dirs, debug=False)
    finally:
        for f in tmp_files:
            try:
                os.unlink(f)
            except OSError:
                pass

    return ast_root, verilog_files


def run_ast(design_name: str, force: bool = False, variant: str = "tjin") -> None:
    cfg = get_design_config(design_name, variant=variant)
    output_dir = Path(cfg["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    out_nodes  = output_dir / "ast_nodes.csv"
    out_edges  = output_dir / "ast_edges.csv"
    out_scores = output_dir / "ast_taint_scores.json"

    if out_nodes.exists() and not force:
        print(f"[{design_name}] ast_nodes.csv exists — skipping (use --force)")
        return

    print(f"[{design_name}] Parsing {len(cfg['verilog_files'])} Verilog files ...")
    ast_root, verilog_files = parse_design(cfg)

    sources         = cfg["sources"]
    all_sinks       = cfg["all_sinks"]
    trojan_patterns = cfg["trojan_patterns"]

    # Walk AST
    walker = ASTWalker(sources, all_sinks, trojan_patterns)
    walker.walk(ast_root)
    print(f"[{design_name}] AST nodes: {len(walker.nodes)}")

    # Taint propagation — flat whole-tree pass (intra-module deps + sens-list)
    tainted_signals = propagate_taint(walker)

    # Cross-module taint propagation — instance-qualified walk from the top
    # module, collapsed back to bare names. Catches taint that crosses an
    # Instance boundary (e.g. TSC Trojan(s2, s5, Tj_Trig) -> Trojan.r1/r2),
    # which the flat walk above cannot see (no port-wiring edges).
    crossmodule_tainted, crossmodule_trojan_signals = build_crossmodule_taint(
        ast_root, sources, trojan_patterns, cfg.get("top_module"))
    for sig, dist in crossmodule_tainted.items():
        if sig not in tainted_signals or dist < tainted_signals[sig]:
            tainted_signals[sig] = dist
    print(f"[{design_name}] Tainted signals: {len(tainted_signals)} "
          f"({len(crossmodule_tainted)} via cross-module graph)")

    # Score
    compute_scores(walker, tainted_signals, trojan_patterns, crossmodule_trojan_signals)
    tainted_nodes = sum(1 for n in walker.nodes if n["taint_binary"])
    trojan_nodes  = sum(1 for n in walker.nodes if n["is_on_trojan_path"])
    print(f"[{design_name}] Tainted AST nodes: {tainted_nodes} | "
          f"On Trojan path: {trojan_nodes}")

    # ── Write ast_nodes.csv ──────────────────────────────────────────────────
    with open(out_nodes, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["node_id", "parent_id", "ast_type", "ast_type_enc",
                    "signal_name", "module_name", "lineno", "depth",
                    "timing_sensitive", "taint_binary", "taint_score",
                    "role", "role_enc", "is_on_trojan_path", "dist_source"])
        for nd in walker.nodes:
            w.writerow([
                nd["node_id"], nd["parent_id"], nd["ast_type"],
                nd["ast_type_enc"], nd["signal_name"], nd["module_name"],
                nd["lineno"], nd["depth"], nd["timing_sensitive"],
                nd["taint_binary"], nd["taint_score"],
                nd["role"], nd["role_enc"],
                nd["is_on_trojan_path"], nd["dist_source"],
            ])

    # ── Write ast_edges.csv ──────────────────────────────────────────────────
    with open(out_edges, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["src_id", "dst_id"])
        for nd in walker.nodes:
            if nd["parent_id"] >= 0:
                w.writerow([nd["parent_id"], nd["node_id"]])

    # ── Write ast_taint_scores.json ──────────────────────────────────────────
    # Aggregate per unique signal name (max score across all nodes with that name)
    signal_agg: dict[str, dict] = {}
    for nd in walker.nodes:
        sig = nd["signal_name"]
        if not sig:
            continue
        if sig not in signal_agg or nd["taint_score"] > signal_agg[sig]["taint_score"]:
            signal_agg[sig] = {
                "role":             nd["role"],
                "module_name":      nd["module_name"],
                "taint_binary":     nd["taint_binary"],
                "taint_score":      nd["taint_score"],
                "dist_source":      nd["dist_source"],
                "is_on_trojan_path": nd["is_on_trojan_path"],
                "timing_sensitive": nd["timing_sensitive"],
            }
    with open(out_scores, "w") as f:
        json.dump(signal_agg, f, indent=2)

    # ── Write report ─────────────────────────────────────────────────────────
    from collections import Counter
    type_counts = Counter(nd["ast_type"] for nd in walker.nodes)
    tainted_scores_list = [nd["taint_score"] for nd in walker.nodes if nd["taint_binary"]]

    report_lines = [
        f"AST TAINT REPORT — {design_name}", "=" * 60,
        f"Verilog files    : {len(verilog_files)}",
        f"Total AST nodes  : {len(walker.nodes)}",
        f"Tainted signals  : {len(tainted_signals)}",
        f"Tainted nodes    : {tainted_nodes}  "
        f"({tainted_nodes/len(walker.nodes)*100:.1f}%)",
        f"On Trojan path   : {trojan_nodes}",
        f"Score range      : {min(tainted_scores_list, default=0):.3f} – "
        f"{max(tainted_scores_list, default=0):.3f}",
        "", "TOP AST TYPES", "-" * 40,
    ]
    for t, c in type_counts.most_common(15):
        report_lines.append(f"  {t:<30} {c}")
    report_lines += ["", "TOP TAINTED SIGNALS", "-" * 40]
    top_sigs = sorted(signal_agg.items(),
                      key=lambda x: x[1]["taint_score"], reverse=True)[:20]
    for sig, info in top_sigs:
        report_lines.append(
            f"  {sig:<35} score={info['taint_score']:.3f}  "
            f"dist={info['dist_source']}  role={info['role']}"
        )

    out_report = output_dir / "ast_report.txt"
    with open(out_report, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print(f"[{design_name}] → {out_nodes.name} ({len(walker.nodes)} rows) | "
          f"{out_edges.name} | {out_scores.name} | {out_report.name}")


def main():
    parser = argparse.ArgumentParser(description="Stage 1: PyVerilog AST extraction")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--design", metavar="NAME")
    group.add_argument("--all", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    designs = discover_designs() if args.all else [args.design]
    errors = []
    for name in designs:
        try:
            run_ast(name, force=args.force)
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
