"""
pipeline_config.py — Auto-discovery and config resolution for the IFT pipeline.

Designs are auto-discovered from pipeline/stage0_designs/<DESIGN>/ directories —
this is the only place users need to drop a design to have it picked up by
`--all` or `--design <name>`. Sources, sinks, and trojan patterns are inferred
from the Verilog files using heuristics. designs.json is an override file used
only when the heuristics need correction for a specific design.

Usage:
    from config.pipeline_config import get_design_config, discover_designs

    cfg = get_design_config("AES-T2100")
    # cfg["verilog_files"], cfg["sources"], cfg["trojan_sinks"], ...
"""


class UnsupportedDesignError(ValueError):
    """
    Raised when a design cannot be processed by the Verilog-only pipeline.
    Typical cause: VHDL-primary or VHDL-only design (b19, MC8051, etc.).
    """
    pass


import os
import re
import json
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PIPELINE_DIR = Path(__file__).parent.parent.resolve()          # Test/pipeline/
TEST_DIR     = PIPELINE_DIR / "stage0_designs"                 # sole design intake folder
# stage0_designs/TjIn/<design>/*.v and stage0_designs/TjFree/<design>/*.v —
# the user places trojan-inserted and clean-baseline sources directly into
# these pooled folders, pre-separated. No further tjin/tjfree disambiguation
# is done by the pipeline; the folder the file lives in is authoritative.
TJIN_DIR   = TEST_DIR / "TjIn"
TJFREE_DIR = TEST_DIR / "TjFree"

OUTPUTS_DIR  = PIPELINE_DIR / "outputs"
OVERRIDES_FILE    = PIPELINE_DIR / "config" / "designs.json"
TROJAN_TYPES_FILE = PIPELINE_DIR / "config" / "trojan_types.json"

# ---------------------------------------------------------------------------
# Scoring weights (QFlow default; TC model uses these too)
# ---------------------------------------------------------------------------

SCORING = {
    "W_PATH":   0.40,
    "W_FANOUT": 0.20,
    "W_WIDTH":  0.15,
    "W_ROLE":   0.25,
    "MAX_FANOUT": 20,
    "ROLE_BONUS": {
        "source":            1.0,
        "sink":              0.9,
        "trojan":            0.85,
        "key_schedule":      0.7,
        "timing_sensitive":  0.75,
        "logic":             0.3,
        "internal":          0.2,
    },
}

# Canonical role → [0,1] feature encoding (GNN export + viz). Single source of truth.
ROLE_ENC_NORM = {
    "source":              1.0,
    "sink":                0.8,
    "trojan_intermediate": 0.6,
    "key_intermediate":    0.4,
    "logic":               0.2,
    "internal":            0.1,
    "not_in_dfg":          0.0,
    "not_in_ast":          0.0,
    "excluded":            0.0,
    "?":                   0.0,
}

# Stage 4 fusion thresholds. Centralised so sensitivity sweeps are trivial.
FUSION_THRESHOLDS = {
    "AGREE_THRESH":      0.15,   # |DFG − AST| within this → agreement
    "HIGH_THRESH":       0.25,   # score ≥ this → "high"
    "AST_DETECT_THRESH": 0.08,   # AST-only detection floor (DFG < AST*0.5)
    "ANOMALY_DELTA":     0.15,   # |delta_score| > this → is_anomaly=1
}

# GLRA Transmission Cost weights (used with --tc-model flag)
TC_WEIGHTS = {
    "$xor":   0.1, "$xnor":  0.1,
    "$not":   0.1, "$buf":   0.1,
    "$or":    0.1, "$nor":   0.1,
    "$mux":   0.3,
    "$dff":   0.5, "$adff":  0.5, "$aldff": 0.5, "$sdff": 0.5,
    "$eq":    0.6, "$ne":    0.6, "$lt":    0.6, "$le":   0.6,
    "$and":   0.8, "$nand":  0.8,
    "default": 0.2,
}

# QtFlow — Phase 2 timing-sensitive scoring weights (used by stage3_scoring/qtflow_dfg.py).
# TLS = W_TIMING_TAINT*tt_tgt + W_PROX*prox + W_CTRL_COUNT*ctrl + W_CYC_DELTA*delta_cyc
QTFLOW = {
    "W_TIMING_TAINT":      0.40,   # dominant — presence of timing taint in target
    "W_PROX":              0.25,   # 1/(1+cycle_depth); nearer cycle-wise = leakier
    "W_CTRL_COUNT":        0.20,   # control-flow cells crossed on source→sig path
    "W_CYC_DELTA":         0.15,   # target reaches earlier (fewer cycles) than golden
    "CTRL_SATURATION":     5,      # ctrl_channels_reached ≥ this → ctrl = 1.0
    "CYCLE_SIM_THRESH":    1,      # |c_tgt − c_gld| ≤ this → TIMING_CONTROL (vs ELEVATED)
    "GHOST_TLS":           0.5,    # neutral-marker TLS for ghost_tainted signals
    "MAX_CYCLES":          64,     # cycle-depth BFS ceiling — protects against DFF
                                    # feedback loops that otherwise re-queue forever.
                                    # 64 is well beyond any realistic AES pipeline depth.
    # Cells whose taint on a *gating* input converts data-taint into timing-taint.
    "TIMING_CTRL_CELLS":   [
        "$mux", "$pmux",
        "$eq", "$ne", "$lt", "$gt", "$le", "$ge",
        "$memrd_v2", "$memrd", "$memwr_v2",
        "$dlatch",
    ],
    # Edge-triggered cells — each crossing increments cycle depth by 1.
    # $dlatch is level-sensitive/transparent → NOT a cycle boundary here.
    "CYCLE_BOUNDARY_CELLS": ["$dff", "$adff", "$sdff", "$aldff"],
    # For cells in this map, only a tainted gating port (not data ports) emits
    # timing taint. Cells not listed (e.g. $eq/$ne/...) treat any tainted input
    # as a timing-leak source.
    "GATING_PORT": {
        "$mux":        "S",
        "$pmux":       "S",
        "$memrd_v2":   "ADDR",
        "$memrd":      "ADDR",
        "$memwr_v2":   "ADDR",
        "$dlatch":     "EN",
    },
}

# ---------------------------------------------------------------------------
# Core module names — NOT considered trojan modules during auto-detection
# ---------------------------------------------------------------------------

CORE_MODULE_NAMES = {
    "aes_128", "round", "one_round", "final_round",
    "table", "table_lookup", "expand_key_128",
    "top",         # T2100 wrapper (legit top-level)
}

# Testbench file patterns to exclude from synthesis.
# Covers: tb_TOP.v, tbTOP.v, test_aes_128.v, AES_tb.v, battery_tb.v
TESTBENCH_PATTERNS = re.compile(r'^(tb|test)|_tb\.v$', re.IGNORECASE)

# Verilog keywords excluded from inline-trojan comment-region extraction —
# without this, a window of code around a marker comment picks up `wire`,
# `if`, `end`, etc. as "trojan patterns", which would then substring-match
# almost every node in golden_delta.py's masking pass.
_VERILOG_KEYWORDS = {
    "wire", "reg", "input", "output", "inout", "module", "endmodule",
    "always", "begin", "end", "if", "else", "case", "endcase", "default",
    "assign", "posedge", "negedge", "parameter", "localparam", "function",
    "endfunction", "integer", "genvar", "for", "while", "logic", "signed",
}

# Marks a `//`-comment line as a real inline-trojan-region marker rather
# than a boilerplate header field (e.g. `// Module Name: Trojan_Trigger`,
# which mentions "trojan" only because that's the module's name, not because
# the comment is annotating a trojan-specific code region).
_TROJAN_MARKER_RE = re.compile(r'//.*trojan', re.IGNORECASE)
_HEADER_TEMPLATE_RE = re.compile(
    r'^\s*//\s*(module name|company|engineer|create date|revision|'
    r'description|dependencies|additional comments|project name|'
    r'target devices|tool versions)',
    re.IGNORECASE,
)


_CONDITION_RE = re.compile(r'\bif\s*\(([^)]*)\)')
_ASSIGN_RHS_RE = re.compile(r'(?:<=|=)\s*([^;]+);')


def _extract_inline_trojan_region(verilog_file: Path, window: int = 6):
    """Comment-anchored trojan-region extraction for inline (no separate
    trojan module) designs, which mark trojan code regions with comments like
    `// Hardware Trojan signal declaration` / `// Trojan Payload execution`
    rather than a distinct module.

    Returns None if the file has no real trojan-marker comment (caller falls
    back to the existing whole-module-sweep behavior — this function only
    narrows/redirects behavior when it has positive evidence to act on).
    Otherwise returns a dict:
      - patterns: candidate signal names near any marker (for trojan_patterns /
        golden-baseline masking)
      - marker_text: the marker comment lines themselves (for category
        classification — see _classify_trojan_effect)
      - condition_idents: identifiers inside `if (...)` conditions in the
        marker windows — candidate taint sources for a `dos`-category trojan
        (the signal gating the malicious stall/block)
      - assign_rhs_idents: identifiers on assignment right-hand-sides in the
        marker windows — candidate taint sources for a `corruption`/`spoofing`
        -category trojan (the legitimate data the payload corrupts/replaces)
    """
    lines = verilog_file.read_text(encoding='utf-8', errors='ignore').splitlines()
    marker_idxs = [
        i for i, line in enumerate(lines)
        if _TROJAN_MARKER_RE.search(line) and not _HEADER_TEMPLATE_RE.search(line)
    ]
    if not marker_idxs:
        return None

    # (?<!') excludes the radix/digit suffix of a numeric literal like
    # `2'b11` or `8'h66` — \b alone matches right after the `'`, so `b11`/
    # `h66` would otherwise be captured as if they were real identifiers.
    ident_re = re.compile(r"(?<!')\b[A-Za-z_]\w+\b")

    def clean_idents(text):
        return {
            m.group(0) for m in ident_re.finditer(text)
            if len(m.group(0)) > 2 and m.group(0) not in _VERILOG_KEYWORDS
            and not m.group(0)[0].isdigit()
        }

    patterns, condition_idents, assign_rhs_idents = set(), set(), set()
    marker_text = [lines[i] for i in marker_idxs]
    for idx in marker_idxs:
        lo, hi = max(0, idx - 1), min(len(lines), idx + window)
        for line in lines[lo:hi]:
            code = re.sub(r'//.*', '', line)  # drop trailing comment on the line itself
            patterns |= clean_idents(code)
            for cm in _CONDITION_RE.finditer(code):
                condition_idents |= clean_idents(cm.group(1))
            for am in _ASSIGN_RHS_RE.finditer(code):
                assign_rhs_idents |= clean_idents(am.group(1))

    return {
        "patterns": sorted(patterns),
        "marker_text": marker_text,
        "condition_idents": sorted(condition_idents),
        "assign_rhs_idents": sorted(assign_rhs_idents),
    }


def classify_trojan_effect(marker_text: list) -> str:
    """Classify inline trojan-marker comment text into the controlled
    taxonomy in config/trojan_categories.json (leak_info/dos/corruption/
    spoofing/other). First matching category wins; used both to pick a
    category-appropriate taint-source fallback in _auto_detect() and, later,
    as ground truth for the pilot's fusion-category agreement check.
    """
    categories = _load_trojan_categories()
    text = " ".join(marker_text).lower()
    for category, spec in categories.items():
        if category == "other":
            continue
        for kw in spec.get("keywords", []):
            if re.search(kw, text):
                return category
    return "other"


_TROJAN_CATEGORIES_CACHE = None


def _load_trojan_categories() -> dict:
    global _TROJAN_CATEGORIES_CACHE
    if _TROJAN_CATEGORIES_CACHE is None:
        path = Path(__file__).parent / "trojan_categories.json"
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        _TROJAN_CATEGORIES_CACHE = {k: v for k, v in raw.items() if not k.startswith("_")}
    return _TROJAN_CATEGORIES_CACHE

# ---------------------------------------------------------------------------
# Heuristic auto-discovery
# ---------------------------------------------------------------------------

def _parse_ports_from_verilog(verilog_file: Path):
    """
    Return list of (direction, width, name) tuples from a Verilog module.
    Handles both traditional (port-list + separate declarations) and ANSI
    (inline port declarations) styles.
    """
    text = verilog_file.read_text(encoding='utf-8', errors='ignore')
    ports = []

    # Match any input/output declaration, with optional reg/wire keyword and width.
    # Covers both:
    #   Traditional:  input [127:0] key, state;
    #   ANSI inline:  input r1,   /  output trigger
    port_re = re.compile(
        r'\b(input|output|inout)\s+'
        r'(?:(?:reg|wire|logic)\s+)?'         # optional type qualifier
        r'(?:\[(\d+)\s*:\s*(\d+)\])?\s*'      # optional [high:low]
        r'([\w]+(?:\s*,\s*[\w]+)*)'            # one or more signal names
        r'(?=\s*[,;)])',                        # followed by comma, semicolon, or )
        re.MULTILINE
    )
    for m in port_re.finditer(text):
        direction = m.group(1)
        high  = int(m.group(2)) if m.group(2) else 0
        low   = int(m.group(3)) if m.group(3) else 0
        width = abs(high - low) + 1
        names = [n.strip() for n in m.group(4).split(',') if n.strip()]
        for name in names:
            if name and not name[0].isdigit():
                ports.append((direction, width, name))
    return ports


def _get_module_names_in_dir(verilog_dir: Path, files=None):
    """Return set of module names defined in *.v files (excluding testbenches).

    `files` optionally restricts the scan to a specific file list (Path
    objects) rather than everything in `verilog_dir` — used when a
    self-contained `topModule.v` has made sibling files redundant (see
    _auto_detect) and they must be excluded from every subsequent scan, not
    just the Yosys file list.
    """
    module_re = re.compile(r'^\s*module\s+(\w+)', re.MULTILINE)
    modules = set()
    for vf in (files if files is not None else verilog_dir.glob("*.v")):
        if TESTBENCH_PATTERNS.search(vf.name):
            continue
        text = vf.read_text(encoding='utf-8', errors='ignore')
        for m in module_re.finditer(text):
            modules.add(m.group(1))
    return modules


def _find_top_module(tjin_dir: Path, verilog_files: list) -> tuple:
    """
    Identify the top-level module name and its .v file.
    Strategy (in order):
      1. top.v — explicit conventional name
      1b. topModule.v — pre-normalized wrapper (declares `module top`), used by
          some designs' flattened single-file exports.
      2. *_top.v — wb_conmax_top.v style
      3. aes_128.v — AES designs without a top wrapper
      4. The module defined but NOT instantiated by any other module in the design
      5. First .v file alphabetically (last resort)
    Returns (module_name, Path).
    """
    # 1. Explicit top.v
    if (tjin_dir / "top.v").exists():
        return "top", tjin_dir / "top.v"

    # 1b. topModule.v (declares `module top`)
    if (tjin_dir / "topModule.v").exists():
        return "top", tjin_dir / "topModule.v"

    # 2. *_top.v
    top_candidates = [f for f in verilog_files if f.endswith("_top.v")]
    if top_candidates:
        chosen = top_candidates[0]
        return Path(chosen).stem, tjin_dir / chosen

    # 3. aes_128.v
    if (tjin_dir / "aes_128.v").exists():
        return "aes_128", tjin_dir / "aes_128.v"

    # 4. Find the true top: defined but never instantiated by any peer module
    module_re = re.compile(r'^\s*module\s+(\w+)', re.MULTILINE)
    inst_re    = re.compile(r'^\s*(\w+)\s+\w+\s*\(', re.MULTILINE)

    defined = {}      # name -> Path
    instantiated = set()

    for fname in verilog_files:
        vf = tjin_dir / fname
        text = vf.read_text(encoding='utf-8', errors='ignore')
        for m in module_re.finditer(text):
            defined[m.group(1)] = vf
        for m in inst_re.finditer(text):
            instantiated.add(m.group(1))

    top_mods = {n: p for n, p in defined.items() if n not in instantiated}
    if top_mods:
        name, path = next(iter(top_mods.items()))
        return name, path

    # 5. Last resort: first .v file
    if verilog_files:
        stem = Path(verilog_files[0]).stem
        return stem, tjin_dir / verilog_files[0]

    raise FileNotFoundError(f"Cannot determine top module in {tjin_dir}")


def _collect_signal_idents(verilog_file: Path) -> set:
    """Return real signal identifiers (ports + reg/wire declarations) in a
    Verilog file — deliberately excludes parameter/localparam names, which
    are compile-time constants and never appear as netlist nets."""
    text = verilog_file.read_text(encoding='utf-8', errors='ignore')
    idents = {name for _, _, name in _parse_ports_from_verilog(verilog_file)}
    # [^;\n]+ (not [^;]+) — restricts each match to a single line, so a
    # multi-line ANSI port list with no per-port semicolon (e.g. `input wire
    # [DATAWIDTH-1:0] a,\n    input wire ... b,`) can't make this regex's
    # greedy capture bleed across lines into unrelated keywords/params.
    decl_re = re.compile(r'\b(reg|wire|logic)\b(?:\s*\[[^\]]*\])?\s+([^;\n]+);', re.MULTILINE)
    ident_re = re.compile(r"(?<!')\b[A-Za-z_]\w+\b")
    for m in decl_re.finditer(text):
        idents |= {im.group(0) for im in ident_re.finditer(m.group(2))}
    return idents


def _resolve_against_signals(name: str, valid_idents: set) -> str | None:
    """Resolve a candidate source name against a file's real declared
    signals, tolerating underscore-stripping mismatches between a stale
    sibling source file (underscored names) and the file Yosys actually
    synthesizes (often flattened/renamed, e.g. `trojan_counter_trigger` vs
    `trojancountertrigger`). Returns None if no real signal matches at all
    (e.g. the name is a parameter, or a numeric-literal scan artifact)."""
    if name in valid_idents:
        return name
    norm = name.replace('_', '').lower()
    for ident in valid_idents:
        if ident.replace('_', '').lower() == norm:
            return ident
    return None


def _auto_detect(design_name: str, design_dir: Path, variant: str = "tjin") -> dict:
    """Infer all config fields from the Verilog source directory.

    variant: "tjin" (default) scans stage0_designs/TjIn/<design_name>/
    (trojan-inserted). "tjfree" scans stage0_designs/TjFree/<design_name>/
    (clean baseline) instead — used for graph-level clean-vs-trojan
    classification (Stage 6). All the same heuristics apply; TjFree
    naturally yields no/near-no trojan_patterns since the trojan module
    files don't exist in that source tree.

    `design_dir` is `stage0_designs/TjIn/<design_name>/` — the pipeline
    trusts the pooled TjIn/TjFree folder split as-is, no further
    disambiguation.
    """
    tjin_dir = design_dir
    tjfree_dir = TJFREE_DIR / design_name

    if not tjin_dir.exists():
        raise FileNotFoundError(f"No TjIn source found for {design_dir}")
    if variant == "tjfree" and not tjfree_dir.exists():
        raise FileNotFoundError(f"No TjFree source found for {design_name}")

    scan_dir = tjfree_dir if variant == "tjfree" else tjin_dir

    # --- Verilog files (exclude testbenches) ---
    verilog_files = sorted(
        vf.name for vf in scan_dir.glob("*.v")
        if not TESTBENCH_PATTERNS.search(vf.name)
    )

    # --- Top module and its file ---
    top_module, top_file = _find_top_module(scan_dir, verilog_files)

    # --- Drop sibling files made redundant by topModule.v ---
    # Some designs ship a `topModule.v` alongside their original file(s).
    # Two distinct shapes, handled separately (conflating them caused a real
    # bug: see below):
    #
    # Case A — topModule.v itself WON top-module selection (no `top.v` etc.
    # exists). It's sometimes a thin wrapper whose module name doesn't
    # collide with any sibling (topModule.v declares only `top`, the sibling
    # declares a different name — both needed). Other times a sibling IS a
    # raw duplicate/renamed-flattened copy redeclaring the same module
    # name(s) as topModule.v. Drop only the siblings that actually collide
    # with topModule.v's own names.
    #
    # Case B — a DIFFERENT file won top-module selection (e.g. `top.v`, which
    # has priority over topModule.v). Here topModule.v is itself the
    # redundant self-contained flattened copy of the WHOLE design, including
    # the trojan module. Using it as a collision reference (as Case A does)
    # is wrong: it can wrongly drop the design's genuine trojan module
    # because topModule.v's internal flattened copy happens to declare
    # equivalent module names — silently desynthesizing the trojan. Simply
    # drop topModule.v itself; leave every other file untouched.
    _topmodule_file = scan_dir / "topModule.v"
    if top_file.name == "topModule.v":
        _module_re = re.compile(r'^\s*module\s+(\w+)', re.MULTILINE)
        _top_mod_names = set(_module_re.findall(top_file.read_text(encoding='utf-8', errors='ignore')))
        _kept = []
        for fname in verilog_files:
            if fname == top_file.name:
                _kept.append(fname)
                continue
            _sibling_names = set(_module_re.findall((scan_dir / fname).read_text(encoding='utf-8', errors='ignore')))
            if _sibling_names & _top_mod_names:
                continue  # redundant with topModule.v — drop
            _kept.append(fname)
        verilog_files = _kept
    elif _topmodule_file.exists() and _topmodule_file.name in verilog_files:
        verilog_files = [f for f in verilog_files if f != _topmodule_file.name]

    # All subsequent scans (module names, trojan patterns, sinks) must respect
    # the same restricted file set as Yosys/AST — otherwise a dropped sibling
    # file would still leak its (redundant/renamed) identifiers into
    # trojan_patterns even though it's no longer part of the synthesized design.
    _active_files = [scan_dir / f for f in verilog_files]

    # --- Sources and sinks from port analysis ---
    source_keywords = re.compile(r'\b(key|state|plaintext|secret)\b', re.IGNORECASE)
    trojan_sink_keywords = re.compile(r'\b(antena|antenna|leak|trigger|tj_|tsc)\b', re.IGNORECASE)

    ports = _parse_ports_from_verilog(top_file)
    sources = []
    all_sinks = []
    trojan_sinks = []

    for direction, width, name in ports:
        if direction == "input" and width >= 64 and source_keywords.search(name):
            sources.append(name)
        elif direction == "output":
            all_sinks.append(name)
            if trojan_sink_keywords.search(name):
                trojan_sinks.append(name)

    # --- Trojan module patterns ---
    all_modules = _get_module_names_in_dir(scan_dir, files=_active_files)
    trojan_module_names = all_modules - CORE_MODULE_NAMES
    # Filter out short (≤2 char) names — these are AES S-box primitives, not trojans
    trojan_module_names = {m for m in trojan_module_names if len(m) > 2}
    trojan_patterns = list(trojan_module_names) if trojan_module_names else ["TSC", "Trigger"]

    # --- Inline-trojan comment-region scan ---
    # When the design's ENTIRE non-core implementation lives in a single file
    # (no separate Trojan/TSC-style module), the sweep below (which treats
    # any non-core FILE as wholly trojan) would mask out the whole circuit
    # rather than just the trojan, degenerating golden-baseline delta scoring
    # to ~0 everywhere. Verified safe for all 36 stage0_designs designs: this
    # branch only fires when there is exactly one non-core, non-testbench
    # file AND it contains a real (non-header-template) `// ... trojan ...`
    # comment — true only for the 4 PIC16F84-T* designs, all of which
    # already carry an explicit `trojan_patterns` override in designs.json
    # that wins regardless of what auto-detect computes here.
    _noncore_files = [
        vf for vf in _active_files
        if not TESTBENCH_PATTERNS.search(vf.name)
        and vf.stem not in CORE_MODULE_NAMES
        and vf.resolve() != top_file.resolve()
    ]
    _inline_region = None
    if len(_noncore_files) == 1:
        _inline_region = _extract_inline_trojan_region(_noncore_files[0])
    trojan_effect = "unknown"
    if _inline_region is not None:
        trojan_module_names = set()  # the sole non-core file is the design itself, not a trojan module
        trojan_patterns = _inline_region["patterns"] or ["TSC", "Trigger"]

        # --- Category-aware source fallback (config/trojan_categories.json) ---
        # Don't force the confidentiality key|state|plaintext|secret heuristic
        # onto non-leakage designs (DoS/corruption/spoofing effects have no
        # secret to leak). Only fall back when the port-based scan above
        # found nothing — a genuine leakage design's `key`/`state` port match
        # always takes priority.
        if not sources:
            trojan_effect = classify_trojan_effect(_inline_region["marker_text"])
            if trojan_effect == "dos":
                sources = _inline_region["condition_idents"]
            elif trojan_effect in ("corruption", "spoofing"):
                sources = _inline_region["assign_rhs_idents"]
            elif trojan_effect == "leak_info":
                sources = _inline_region["assign_rhs_idents"] or _inline_region["condition_idents"]
            # "other": leave sources empty — no confident category-specific
            # guess; surfaced via taint_diagnostics.json (stage2_ift) for
            # manual designs.json review rather than a forced heuristic.

    # --- Resolve sources against the file Yosys actually synthesizes ---
    # Some designs ship a stale sibling source file (underscored names)
    # alongside the real top_file (often flattened/renamed) — sources
    # auto-detected from the stale sibling then never match any
    # post-synthesis net, so taint propagation silently finds nothing.
    # Resolve/repair here rather than downstream where the mismatch just
    # looks like "no taint" or "no QtFlow scores".
    if sources:
        _top_idents = _collect_signal_idents(top_file)
        sources = [
            r for r in (_resolve_against_signals(s, _top_idents) for s in sources)
            if r is not None
        ]

    # Also add register/wire names declared inside non-core (trojan) Verilog files.
    # These become the signal-level trojan patterns for AST classification.
    # e.g. TSC.v declares SECRETKey, COUNTER, LEAKBit, INV1_out ... INV11_out
    # Handle comma-separated declarations on one line: wire INV1_out, INV2_out, ...;
    # Skipped entirely when the inline comment-region scan above already ran —
    # sweeping the whole file here would undo the point of that narrower scan.
    decl_line_re = re.compile(
        r'\b(reg|wire)\b'          # type keyword
        r'(?:\s*\[[^\]]*\])?\s+'   # optional width [n:m]
        r'([^;]+);',               # everything up to semicolon
        re.MULTILINE
    )
    ident_re = re.compile(r"(?<!')\b([A-Za-z_]\w+)\b")
    if _inline_region is None:
        for vf in _active_files:
            if TESTBENCH_PATTERNS.search(vf.name):
                continue
            if vf.stem in CORE_MODULE_NAMES:
                continue
            text = vf.read_text(encoding='utf-8', errors='ignore')
            for m in decl_line_re.finditer(text):
                names_part = m.group(2)
                for ident in ident_re.finditer(names_part):
                    sig_name = ident.group(1)
                    if len(sig_name) > 2 and sig_name not in trojan_patterns:
                        trojan_patterns.append(sig_name)

    # --- Scan all source files for trojan sink signals (output ports of non-core modules) ---
    for vf in _active_files:
        if TESTBENCH_PATTERNS.search(vf.name):
            continue
        if vf.stem in CORE_MODULE_NAMES:
            continue
        for direction, width, name in _parse_ports_from_verilog(vf):
            if direction == "output" and trojan_sink_keywords.search(name):
                if name not in trojan_sinks:
                    trojan_sinks.append(name)

    return {
        "design_name":    design_name,
        "design_dir":     str(design_dir),
        "variant":        variant,
        "verilog_dir":    str(scan_dir),
        "verilog_files":  verilog_files,
        "tjfree_dir":     str(tjfree_dir) if tjfree_dir.exists() else None,
        "top_module":     top_module,
        "sources":        sources,
        "all_sinks":      all_sinks,
        "trojan_sinks":   trojan_sinks,
        "trojan_patterns": trojan_patterns,
        "ghost_tainted":  [],          # Override in designs.json if needed
        "trojan_type":    "unknown",   # Override in designs.json
        # Populated only for inline-trojan designs classified via the
        # comment-marker scan above (config/trojan_categories.json); "unknown"
        # here means get_design_config()'s trojan_types.json fallback should
        # still apply — see the explicit (not setdefault) merge there.
        "trojan_effect":  trojan_effect,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_TROJAN_TYPES_CACHE: dict | None = None


def load_trojan_types() -> dict:
    """Return the Trust-Hub trojan-type catalogue keyed by design name.

    Falls back to {} if the file is missing; loaded once and memoised.
    """
    global _TROJAN_TYPES_CACHE
    if _TROJAN_TYPES_CACHE is None:
        if TROJAN_TYPES_FILE.exists():
            with open(TROJAN_TYPES_FILE) as f:
                raw = json.load(f)
            _TROJAN_TYPES_CACHE = {k: v for k, v in raw.items() if not k.startswith("_")}
        else:
            _TROJAN_TYPES_CACHE = {}
    return _TROJAN_TYPES_CACHE


def discover_designs() -> list[str]:
    """Return sorted list of all design names found in stage0_designs/TjIn/."""
    if not TJIN_DIR.exists():
        return []
    return sorted(
        d.name for d in TJIN_DIR.iterdir()
        if d.is_dir() and any(d.glob("*.v"))
    )


def _locate_design_dir(design_name: str) -> Path:
    """Resolve a design name to its source directory under stage0_designs/TjIn/."""
    design_dir = TJIN_DIR / design_name
    if design_dir.exists():
        return design_dir
    raise FileNotFoundError(
        f"Design directory not found for {design_name!r} — expected "
        f"{design_dir} (drop the design into stage0_designs/TjIn/)"
    )


def get_design_config(design_name: str, variant: str = "tjin") -> dict:
    """
    Return the fully resolved config for a design.
    Auto-detected values are merged with any overridesfrom designs.json.

    variant: "tjin" (default, trojan-inserted) or "tjfree" (clean baseline —
    used for graph-level clean-vs-trojan classification in Stage 6). designs.json
    overrides are keyed by design name only and always applied to both variants;
    trojan-specific overrides (ghost_tainted, keep_signals) are harmless no-ops
    on a tjfree run since there's no trojan netlist for them to match against.
    """
    design_dir = _locate_design_dir(design_name)

    # Auto-detect base config
    cfg = _auto_detect(design_name, design_dir, variant=variant)

    # Load overrides
    if OVERRIDES_FILE.exists():
        with open(OVERRIDES_FILE, encoding="utf-8") as f:
            overrides = json.load(f)
        if design_name in overrides:
            cfg.update(overrides[design_name])

    # Fall through to the Trust-Hub catalogue if neither auto-detect nor the
    # designs.json override supplied a trojan_type. Populates trojan_family,
    # trojan_activation, trojan_effect for downstream viz/reporting.
    types = load_trojan_types().get(design_name)
    if types:
        cfg.setdefault("trojan_family", types.get("family", "other"))
        cfg.setdefault("trojan_activation", types.get("activation", "unknown"))
        # Explicit (not setdefault): _auto_detect() always sets trojan_effect,
        # possibly to "unknown" for legacy designs (their trojans live in a
        # separate module, so the inline comment-marker classifier never
        # fires) — the trojan_types.json catalogue value should still win in
        # that case rather than being silently shadowed by the always-present key.
        if cfg.get("trojan_effect", "unknown") == "unknown":
            cfg["trojan_effect"] = types.get("effect", "unknown")
        if cfg.get("trojan_type", "unknown") == "unknown":
            cfg["trojan_type"] = types.get("family", "unknown")
    else:
        cfg.setdefault("trojan_family", cfg.get("trojan_type", "unknown"))
        cfg.setdefault("trojan_activation", "unknown")
        cfg.setdefault("trojan_effect", "unknown")

    # Resolve output directory — tjfree runs get a separate namespace so they
    # never clobber the trojan-inserted run's outputs for the same design.
    output_name = f"{design_name}__tjfree" if variant == "tjfree" else design_name
    cfg["output_dir"] = str(OUTPUTS_DIR / output_name)

    return cfg


def get_output_path(design_name: str, filename: str) -> Path:
    """Return the full path for a pipeline output file."""
    return OUTPUTS_DIR / design_name / filename


if __name__ == "__main__":
    # Quick self-test: print auto-detected config for all designs
    designs = discover_designs()
    print(f"Discovered {len(designs)} designs: {designs}\n")
    for name in designs:
        try:
            cfg = get_design_config(name)
            print(f"[{name}]")
            print(f"  top_module    : {cfg['top_module']}")
            print(f"  verilog_files : {cfg['verilog_files']}")
            print(f"  sources       : {cfg['sources']}")
            print(f"  all_sinks     : {cfg['all_sinks']}")
            print(f"  trojan_sinks  : {cfg['trojan_sinks']}")
            print(f"  trojan_patterns: {cfg['trojan_patterns']}")
            print(f"  ghost_tainted : {cfg['ghost_tainted']}")
            print(f"  trojan_type   : {cfg['trojan_type']}")
            print()
        except Exception as e:
            print(f"[{name}] ERROR: {e}\n")

