"""
stage1_extract/ast_crossmodule.py — shared cross-module AST helpers.

Extracted from stage3_scoring.qtflow_ast's ASTTimingWalker so the base AST
taint scorer (run_ast.py) and the timing scorer (qtflow_ast.py) share one
instance-qualification implementation instead of two copies that can drift.

Instance qualification prefixes every identifier inside an instantiated
module's body with its instance path (e.g. 'r1' -> 'Trojan.r1'), so two
modules that happen to reuse a port/signal name (key, clk, ...) don't
collide in a shared flat rhs_deps namespace.
"""

# Cap on instance-nesting depth when recursing into instantiated module
# bodies. Trust-Hub designs nest a handful of levels deep (aes_128 ->
# one_round -> table_lookup -> S4 -> S); this guards against runaway
# recursion on any malformed or self-referential module graph.
MAX_INSTANCE_DEPTH = 12


def collect_module_defs(ast_root) -> dict:
    """Index every ModuleDef in the file by name, so Instance nodes can be
    resolved to their callee module body for qualified cross-module walking."""
    mods: dict = {}

    def _rec(node):
        if type(node).__name__ == "ModuleDef" and getattr(node, "name", None):
            mods[str(node.name)] = node
        if hasattr(node, "children"):
            for c in node.children():
                if c is not None:
                    _rec(c)

    _rec(ast_root)
    return mods


def formal_port_names(module_def) -> list:
    """Ordered formal port names for a ModuleDef, e.g. ['r1', 'r2', 'trigger']."""
    names = []
    try:
        for port in module_def.portlist.ports:
            decl = getattr(port, "first", None)
            name = getattr(decl, "name", None) or getattr(port, "name", None)
            if name:
                names.append(str(name))
    except Exception:
        pass
    return names


def qualify(name: str, instance_path: list) -> str:
    """Prefix a bare identifier with the current instance path, e.g.
    'r1' -> 'Trojan.r1' when walking inside the 'Trojan' instance body."""
    if not instance_path:
        return name
    return ".".join(instance_path) + "." + name


def qualify_all(names, instance_path: list) -> set:
    return {qualify(n, instance_path) for n in names}


# Signal names that are almost always pure clock/reset control and should be
# excluded from trojan-instance tagging — a clk/rst wired into a trojan
# module's ports is not itself a trojan signal, it's ordinary infrastructure
# every module (trojan or not) needs. Without this filter, any clock/reset
# line connected to a trojan instance gets falsely tagged as trojan-related.
_CLOCK_RESET_NAMES = {
    "clk", "clock", "clk_i", "clock_i",
    "rst", "reset", "nrst", "rst_n", "resetn", "rst_i", "reset_i",
    "aclk", "sclk",
}


def is_clock_or_reset(name: str) -> bool:
    n = name.lower()
    if n in _CLOCK_RESET_NAMES:
        return True
    for stem in ("clk", "clock", "reset"):
        if n == stem or n.startswith(stem + "_") or n.endswith("_" + stem):
            return True
    return False


def identify_trojan_modules(trojan_patterns: list) -> set:
    """Pick the subset of trojan_patterns that plausibly name a module.

    Module names are typically capitalised or start with a letter and are
    longer than a few chars. Matching on the full trojan_patterns set would
    also match signal-name patterns (SECRETKey, INV1_out, ...) which are
    not module names — masking their declarations inside a non-trojan module
    would be wrong. Heuristic: treat trojan_patterns as candidate module
    names and let the walk consult the actual ModuleDef during traversal.
    """
    return {p for p in trojan_patterns if len(p) > 2}
