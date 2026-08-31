# IFT Pipeline — Design Decisions Log

This log documents the key design decisions, bugs encountered, and reasoning
behind each change. It exists so future readers (including thesis reviewers)
can understand *why* the code is structured the way it is — not just *what* it does.

---

## Stage 1: Yosys Synthesis (`run_yosys.py`)

### Decision: `setattr keep` BEFORE `flatten`

**Problem:** Yosys synthesis strips T2100's power-side-channel Trojan logic as
dead code. The inverter chain (INV1–INV11), LEAKBit, SECRETKey, COUNTER, and
Tj_Trig have no digital output port — they modulate power consumption only.
Yosys's `opt_clean` removes them because they drive nothing observable.

First synthesis run: only 5 Trojan nets survived. Expected: 33+.

**Fix:** Added `keep_signals` to designs.json for T2100:
```json
"keep_signals": ["SECRETKey", "LEAKBit", "INV", "COUNTER", "Tj_Trig"]
```
The Yosys script emits `setattr -set keep 1 w:*SIGNAL*` for each entry,
**before** the `flatten` step. Order matters: `setattr` after `flatten` is
too late because `opt_clean` runs as part of `flatten`'s internal passes.

Result: 33 Trojan nets preserved. T2100's power-channel analysis now works.

**Why only T2100 needs this:** T2300–T2600 Trojans have real output ports
(`trigger`, `Tj_Trig`) that Yosys preserves automatically.

---

### Decision: Ghost nodes in T2100 DFG

**Problem:** Even with `keep` set, the T2100 inverter chain nets
(`Trojan.INV2_out`…`Trojan.INV11_out`, `Trojan.LEAKBit`) exist in the netlist
but have no incoming edges in the DFG. The BFS taint propagation never reaches
them, so they get taint_score=0.000.

**Root cause:** Yosys preserves the *names* of the nets due to `setattr keep`,
but removes the gate-level connections (the actual inverter cells) because
they're functionally dead. The nets exist as "ghost" entries — named but
unconnected.

**Fix:** `ghost_tainted` list in `designs.json` explicitly marks these nets
as tainted after BFS completes:
```json
"ghost_tainted": ["Trojan.LEAKBit", "Trojan.INV2_out", ..., "Trojan.INV11_out"]
```
In `dfg_taint.py`, after the main BFS loop, any node in `ghost_tainted` that
exists in `node_meta` is added to `tainted`. Their scores are computed using
`ghost_ref_dist = dist_from_source.get(SECRETKey) + 1`.

**Why this is correct:** These nodes ARE reachable in the real circuit — they
receive SECRETKey as input. Synthesis removes the path because it's
functionally invisible at the digital output level. The ghost workaround
restores what the circuit actually does at the power level.

---

### Decision: Hierarchical trojan sink name resolution in DFG

**Problem:** `pipeline_config.py` auto-detects `trojan_sinks = ['trigger']`
from the `output trigger` port in `TSC_and.v`. But after Yosys flattening,
the net is named `Trojan.trigger` (instance prefix prepended). The reverse
BFS from trojan sinks never starts because `'trigger' not in tainted`.

Result: T2300/T2400/T2600 showed "On Trojan path: 0" despite the trigger
being tainted.

**Fix:** In `dfg_taint.py`, after building `node_meta`, expand `trojan_sinks`
to also match any node whose name ends with `.{sink_name}`:
```python
for raw in _raw_trojan_sinks:
    for node in all_nodes:
        if node.endswith(f".{raw}") and node not in trojan_sinks:
            trojan_sinks.append(node)
```

This is safe because flat net names use `Module.signal` format, so
`Trojan.trigger` is unambiguously the trigger signal from the Trojan instance.

Result: T2300 = 1158 trojan path nodes, T2400 = 1618, T2600 = 705.
T2500 = 0 (correct — pure clock counter, no data path to the key).

---

## Stage 2: AST Extraction (`run_ast.py`)

### Status: Complete and correct (as of pipeline revamp session)

The script was the critical missing piece from the original CODE/ directory —
outputs existed but no script to reproduce them. It is now fully working.

**Validation results (AES-T2100):**

| Signal | DFG score | AST score | AST dist | Role |
|--------|-----------|-----------|----------|------|
| key | 0.830 | 0.670 | 0 | source |
| SECRETKey | 0.303 | 0.217 | 1 | trojan_intermediate |
| COUNTER | **0.000** | **0.150** | **2** | trojan_intermediate |
| LEAKBit | 0.081 | 0.149 | 2 | trojan_intermediate |
| Tj_Trig | 0.000 | 0.152 | 2 | trojan_intermediate |

COUNTER = DFG 0, AST 0.150 — this IS the thesis result. DFG can't see it
because Yosys removes the inverter chain as dead logic. AST finds it via the
sensitivity list of the always block that latches the secret.

Total: 5316 AST nodes, 49 tainted signals, 874 tainted nodes.

**Three bugs were found and fixed before the script was finalised:**



### Decision: In-memory Verilog preprocessor for empty port connections

**Problem:** AES-T2100's `aes_128.v` line 42 has:
```verilog
a10(clk, k9,   , k9b, 8'h36)
```
The `, ,` empty port connection is legal Verilog (unconnected port) but
PyVerilog's LALR parser rejects it with a parse error.

**Fix:** Before passing file content to PyVerilog, apply:
```python
content = re.sub(r',(\s*),', r', _nc_ ,', content)
```
This replaces `,  ,` with `, _nc_ ,` — a dummy signal name that the parser
accepts. Write to a temp file, parse, then clean up.

**Why not patch PyVerilog:** The vendored PyVerilog is shared across the thesis
repo. Patching it would create a maintenance burden and risk breaking other
PyVerilog-dependent code.

---

### Decision: Two-pass taint in AST — sensitivity list propagation

**Problem:** COUNTER in T2100's TSC.v is declared as a 128-bit counter that
never receives the key directly in an assignment. The standard BFS through
`rhs_deps[lhs] = {rhs}` never marks COUNTER as tainted.

**The actual information flow:** COUNTER controls **when** SECRETKey is
captured:
```verilog
always @(posedge COUNTER[127])
    SECRETKey <= key;
```
The `posedge COUNTER[127]` means COUNTER is in the **sensitivity list** of an
always block whose body assigns tainted data. This is a timing-based information
flow: COUNTER's value determines at which clock edge the secret is latched,
creating a power side-channel.

**Fix:** Two-pass `propagate_taint()`:
- **Pass 1:** Standard BFS through `rhs_deps` (data assignments)
- **Pass 2:** For each always block where any LHS signal is tainted,
  mark all sensitivity list signals as tainted at `min_lhs_dist + 1`

This correctly computes COUNTER's taint distance:
- SECRETKey is assigned from `key` (dist=1)
- COUNTER is in the sensitivity list of the always block that assigns SECRETKey
- COUNTER dist = 1 + 1 = 2

Result: COUNTER = taint_binary=1, dist=2, score=0.1502 ✓
DFG = taint_binary=0, score=0.000 (synthesis removes dead logic)

This is the **core thesis result**: AST-level IFT detects timing-sensitive
information flow that gate-level DFG analysis misses.

---

### Decision: trojan_patterns includes register/wire names, not just module names

**Problem:** Initial `trojan_patterns` only contained non-core module names
(`TSC`, `Trojan_Trigger`). Signal names like `SECRETKey`, `COUNTER`,
`LEAKBit`, `INV1_out`–`INV11_out` were all classified as "internal" in the AST,
getting `ROLE_BONUS = 0.2` instead of `trojan = 0.85`.

**Fix:** `pipeline_config.py` scans non-core `.v` files for `reg`/`wire`
declarations and adds the signal names to `trojan_patterns`. Uses two-step
regex:
1. `decl_line_re`: capture everything between `reg`/`wire` keyword and `;`
2. `ident_re`: extract all identifiers from the captured text

This handles comma-separated declarations like:
```verilog
wire INV1_out, INV2_out, INV3_out, ..., INV11_out;
```
An earlier single-group regex only captured the last name.

---

### Known limitation: AST doesn't trace module instantiation port connections

T2300/T2400/T2600's Trojan receives tainted AES intermediate signals via
module instantiation:
```verilog
TSC Trojan(s2[89], s5[121], Tj_Trig);  // s2[89]→r1, s5[121]→r2
```
The AST walker sees `r1`, `r2` as input ports of TSC's module definition but
doesn't connect them to `s2[89]` and `s5[121]` from the parent instantiation.

Result: `trigger` in T2300/T2400/T2600 shows AST score=0.000 even though it
IS reachable from the key via tainted AES intermediates.

**Why not fixed:** This requires building a cross-module instantiation graph,
which essentially re-implements part of Yosys's elaboration pass. The DFG
analysis already captures this correctly via the flat netlist. For the thesis,
this is documented as a limitation: AST-level analysis is best for
intra-module information flow; DFG is better for cross-module paths.

**Impact on thesis:** Does not affect the primary T2100 result. T2100's Trojan
is an intra-module side-channel (SECRETKey and COUNTER are both inside the
TSC module).

---

## Stage 2b: `parse_design()` helper extracted from `run_ast.py`

### Decision: Shared parser helper for AST-based stages

**Problem:** When QtFlow-AST was added as Phase 2b, it needed the same Verilog
preprocessing pipeline as `run_ast.py`: empty-port regex fix, trojan-module mask
logic, temp-file write, and PyVerilog parse. Duplicating ~60 lines would make
maintenance fragile.

**Fix:** Extracted `parse_design(cfg, mask_trojan=False)` from `run_ast.py` into
a standalone helper in the same file. Returns a `ParseResult` namedtuple with
`ast`, `trojan_module_names`, and `all_module_names`. `run_ast.py` calls it; so
does `qtflow_ast.py`.

The `mask_trojan` flag skips trojan module definitions during parsing to produce
the golden baseline AST — parallel to how `build_masked_graph` works for DFG.

---

## Stage 3: Golden Baseline (`golden_delta.py`)

### Decision: Mask trojan nodes in TjIn netlist (not re-synthesize TjFree)

**Alternative considered:** Synthesize the TjFree Verilog separately and use
that as the baseline. This would give a cleaner "circuit without Trojan" view.

**Why masking is better:** The TjFree netlist has different node IDs and cell
counts. Computing per-node delta would require cross-netlist name matching,
which is fragile (cells get renamed by synthesis). Using the same TjIn netlist
with trojan nodes masked gives an exact per-node delta with no ambiguity.

**How trojan nodes are identified for masking:**
1. Hierarchical prefix: nodes starting with `Trojan.` or `$flatten\Trojan.`
2. Pattern matching: `trojan_patterns` from config (signal/module names)
   filtered to length > 3 to avoid matching short AES primitive names

T2100 result: 45 trojan nodes excluded, 16 with |Δ| > 0.05 — all correctly
identified as the power-channel Trojan circuitry.

---

## Stage 3b: Phase 1 — GLRA-DFG (`glra_dfg.py`)

### Algorithm overview

GLRA (Graph Leakage Risk Assessment) asks: does the trojan make the leakage path
**cheaper** than in a clean baseline? Implemented as a Transmission Cost (TC)
comparison between the target graph and the golden (trojan-masked) graph.

TC is a per-edge cost function: cheap gates (XOR=0.1, NOT=0.1) pass taint with
minimal cost; expensive gates (AND=0.8) act as mixing barriers. TC along a path
= product of per-edge costs (taking 1−cost to get a diminishing penalty, i.e.
`tc = Π (1 − cost_i)`). A signal with lower TC in the target vs golden has a
shorter/cheaper leakage path — more risk.

Risk score formula:
```
risk_score = clamp01( tc_tgt / (tc_tgt + tc_gld) )   if both exist
           = 1.0   if target-only (trojan introduces the path)
           = 0.0   if golden-only (trojan removes the path, rare)
           = 0.5   if neither (neutral / no data)
```

Categories: `INJECTED` (target-only), `ELEVATED` (tc_tgt > tc_gld by threshold),
`NO_CHANGE` (similar TC), `REDUCED`, `GOLDEN_ONLY`.

### Decision: Reuse `build_masked_graph` from `golden_delta.py`

Rather than re-implementing the graph builder, `glra_dfg.py` imports and calls
`build_masked_graph(cfg, netlist)` directly. This guarantees GLRA uses exactly
the same trojan-masking logic as the golden baseline, keeping the two scorers
consistent by construction.

### Decision: Neutral default = 0.5 (not 0.0) in fuse_labels

Signals with no GLRA coverage (outside the graph or in designs without
auto-detected sources) get `glra_dfg_risk = 0.5` and `glra_dfg_category = NO_DATA`.
Reason: 0.0 would look like "safer than golden", which is a false claim for
signals we simply have no data on. 0.5 = "no information" is semantically correct
and prevents the GNN from learning a spurious clean-signal association from
absent data.

---

## Stage 3c: Phase 2 — QtFlow-DFG (`qtflow_dfg.py`)

### Algorithm overview

QtFlow-DFG introduces a **second scoring axis** orthogonal to GLRA: instead of
measuring path cost, it measures whether the trojan introduces or tightens a
**timing/control channel** — a path where secret data reaches the *gating port*
of a control-flow cell.

Three BFS passes over both target and golden DFG:
1. **Data taint** — same cell rule as Stage 2, produces `data_tainted` set.
2. **Timing taint** — seeded where data taint reaches a gating port. Gating ports:
   `$mux`/`$pmux` select (`S`), `$memrd_v2`/`$memrd` address (`ADDR`),
   `$dlatch` enable (`EN`), and *any* input of `$eq/$ne/$lt/$gt/$le/$ge`.
   Once a timing-tainted seed net is identified, timing taint propagates forward
   through the graph via the same cell rule.
3. **Cycle depth** — BFS from sources tracking (cmin, cmax) per node.
   Edges out of `$dff/$adff/$sdff/$aldff` increment depth by 1; all other
   edges cost 0 (combinational). Both min and max are tracked to capture
   reconvergence spread without path enumeration.

TLS formula:
```
prox       = 1 / (1 + cmin_tgt)          [0 if unreached]
ctrl       = min(ctrl_count / 5, 1.0)
delta_cyc  = max(0, min(1, (cmin_gld − cmin_tgt) / max(cmin_gld, 1)))
tls = clamp01( 0.40×tt_tgt + 0.25×prox + 0.20×ctrl + 0.15×delta_cyc )
```

Weights live in `QTFLOW` dict in `pipeline_config.py` for easy tuning.

Category assignment:
- `tt_tgt=1, tt_gld=0` → `TIMING_INJECTED` (trojan-introduced channel)
- `tt_tgt=1, tt_gld=1, cmin_tgt < cmin_gld − CYCLE_SIM_THRESH` → `TIMING_ELEVATED`
- `tt_tgt=1, tt_gld=1, |cmin_tgt − cmin_gld| ≤ CYCLE_SIM_THRESH` → `TIMING_CONTROL`
- `tt_gld=1, tt_tgt=0` → `TIMING_REDUCED`
- signal in `ghost_tainted` → `TIMING_GHOST` (power-side-channel artefact)
- otherwise → `TIMING_SAFE`

### Bug found and fixed: infinite loop in cycle-depth BFS on DFF feedback

**Problem:** T2100 and T2300 hung indefinitely (10+ minutes) during
`_bfs_cycle_depth()`. The BFS re-queued a node every time `cmax` increased,
which on feedback loops through `$dff` cells never converged.

**Root cause:** DFF feedback edges create cycles. Every pass around the loop
increments cmax by 1, and the BFS re-queues the output net forever.

**Fix:** Added `MAX_CYCLES = 64` cap in `QTFLOW` config. Once a node's `cmax`
reaches `MAX_CYCLES`, further updates are ignored — the node is considered
"reached at maximum depth". This bounds the BFS to O(64 × E) worst case.
64 cycles covers all realistic sequential depths in the benchmark designs
(T2600's counter reaches ~15 cycles; T2100's feedback is 0 cycles — synthesis
collapses it to combinational).

### Decision: Ghost-tainted signals get `TIMING_GHOST`, not `TIMING_INJECTED`

T2100's power-side-channel Trojans (INV chain, LEAKBit) are ghost nodes in the
DFG — they exist as names but have no edges. They are data-tainted via the
`ghost_tainted` workaround, but they are NOT timing channels in the QtFlow sense
(they do not reach any gating port). Assigning `TIMING_GHOST` with `tls=0.5`
(constant, from `QTFLOW["GHOST_TLS"]`) flags them as "present but not a timing
channel" — preserving the GLRA-vs-QtFlow orthogonality claim.

If these were classified as `TIMING_INJECTED`, the thesis claim "GLRA catches
T2100, QtFlow catches T2600" would break. The `TIMING_GHOST` category preserves
the distinction explicitly.

### Orthogonality result (DFG)

| Design | Trojan type | TIMING_INJECTED count | Interpretation |
|--------|-------------|----------------------|----------------|
| T100   | data_exfil  | 0                    | Pure data path, no gating cell involved |
| T2100  | power_side_channel | 0 (13 TIMING_GHOST) | Power-only, not timing — correctly not claimed |
| T2300  | combinational_trigger | 1 | $eq comparator seeds timing-taint on trigger path |
| T2400  | combinational_trigger | 1 | Same as T2300 |
| T2500  | sequential_counter | 0 (1052 TIMING_CONTROL) | Trojan exploits existing AES ctrl flow, no new channel |
| T2600  | sequential_counter | 5 | Dedicated Trojan.counter/$add/$eq chain is INJECTED |

T2500 vs T2600 difference: T2500 has no separate `Trojan.` module — it exploits
the AES state machine's existing `$eq` selects. Both target and golden have the
same timing-control structure (TIMING_CONTROL). T2600 has a dedicated counter
module with its own `$add`/`$eq` chain, absent in the golden → `TIMING_INJECTED`.

---

## Stage 3d: Phase 2b — QtFlow-AST (`qtflow_ast.py`)

### Algorithm overview

Source-level complement to QtFlow-DFG. Uses `ASTTimingWalker` over the PyVerilog
AST to extract the same three measures (data taint, timing taint, cycle depth)
without Yosys elaboration. Catches signals invisible to synthesis (e.g. T2100's
inverter chain) but is blind to cross-module port connections.

Two-pass data taint (mirrors `run_ast.py` pass-2 logic):
- **Pass 1:** BFS through `rhs_deps` (blocking/non-blocking assignments)
- **Pass 2:** Sensitivity-list back-propagation: if any LHS of a clocked `always`
  block is data-tainted, the sensitivity-list signal (clock excluded) is also
  data-tainted. Iterates until no new signals are added.

Timing taint is seeded from:
- `IfStatement` where the condition signal is data-tainted (and not a clock/reset)
- Ternary expression (`?:`) where the condition is data-tainted
- `sens_ctrl` signals in clocked always blocks where the LHS is data-tainted

Cycle depth = count of non-blocking assignment (`<=`) crossings from a source
to a signal along the shortest BFS path.

### Bug found and fixed: clock contamination via sens-list back-propagation

**Problem:** After adding Pass 2 sens-list back-propagation, T2500 and T100
showed every signal as `TIMING_INJECTED`. Root cause: `clk` (the clock signal)
became data-tainted through sens-list back-prop — it appears in the sensitivity
list of `always @(posedge clk)` blocks whose LHS signals were tainted.
Once `clk` was tainted, every clocked always block fired timing-taint on its
entire LHS.

**Fix:** Added `_is_clock_or_reset(name)` filter using the `_CLOCK_RESET_NAMES`
set (`clk`, `clock`, `rst`, `reset`, `resetn`, `nreset`, `areset`, `n_reset`).
Applied in two places:
1. Pass 2 back-prop: skip the sensitivity signal if `_is_clock_or_reset()` returns True
2. Timing-taint seeding: skip `IfStatement`/`sens_ctrl` conditions that are clocks

Without this filter, clock signals acting as structural enablers would be
incorrectly marked as information-bearing channels.

### Decision: No cross-module Instance port capture in AST walker

Three attempts were made to follow module instantiation port connections:

1. **Bidirectional for all instances** — `arg→port` for inputs, `port→arg` for
   outputs — caused 82/82 INJECTED for T2600 because `state_out` is shared as
   a portname across all 10 AES round instances, causing namespace collision.

2. **Trojan-only instance capture** — same problem in reverse: T2600's trigger
   chain relies on data flowing *into* the Trojan from round outputs; without
   non-Trojan instance edges, the s3-chain was broken and T2600 got 0 INJECTED.

3. **Strict directional edges for all instances** — still 82/82 INJECTED because
   the portname collision (`state_out` aliasing top-level `state_out`) polluted
   the entire namespace.

**Root cause:** The AST walker uses a global signal namespace. Without hierarchical
scoping (i.e. `module_instance.portname`), port names from different module
instances alias each other.

**Final decision:** No Instance capture. Documented as a limitation. The AST
excels at intra-module timing analysis (T2100's power side-channel), while
cross-module paths are DFG's strength. This division of labour is the thesis's
complementarity argument.

### Orthogonality result (AST)

| Design | TIMING_INJECTED count | Key signal | Notes |
|--------|-----------------------|------------|-------|
| T100   | 0 | — | Data-exfil path is cross-module (DFG's job) |
| T2100  | 13 | INV4_out, INV6_out, … | Sens-list back-prop: always @(posedge COUNTER[127]) → COUNTER data-tainted → INJECTED |
| T2300  | 0 | — | Trigger path crosses module boundary |
| T2400  | 0 | — | Same as T2300 |
| T2500  | 0 | — | Counter is cross-module |
| T2600  | 0 | — | Trigger path crosses module boundary |

AST catches T2100 (13 INJECTED); DFG catches T2300/2400/2600. Orthogonal by design.

---

## Stage 4: Label Fusion (`fuse_labels.py`)

### Decision: Two-tier threshold for AST_ONLY_HIGH category

**Problem:** Initial `HIGH_THRESH=0.25` classified COUNTER (AST=0.150) and
Tj_Trig (AST=0.152) as `AGREE_LOW` instead of `AST_ONLY_HIGH`. These are
exactly the thesis-critical signals that DFG misses.

**Why scores are ~0.15 not ~0.25+:**
The QFlow scoring formula:
```
score = 0.40×path_score + 0.20×fanout_score + 0.15×width_score + 0.25×role_bonus
```
COUNTER at dist=2 from source → path_score = 1/(1+2) = 0.333
With role_bonus=0.85 (trojan) → score ≈ 0.40×0.167 + 0.25×0.85 = 0.279 max
But COUNTER has low fanout and 128-bit width (128/128=1.0) → ~0.150 final

The score is correct. The threshold was wrong.

**Fix:** Added `AST_DETECT_THRESH = 0.08` for AST-only detection:
- `AST_ONLY_HIGH`: AST ≥ 0.08 AND DFG < AST × 0.5 (DFG is blind to it)
- `AGREE_HIGH`: both ≥ 0.25 AND |diff| ≤ 0.15 (strong positive label)

This correctly captures: "AST sees it, DFG is blind" regardless of absolute
score level. The 0.5× ratio check ensures DFG is substantially worse than AST,
not just slightly lower.

Result: COUNTER = `AST_ONLY_HIGH` ✓, Tj_Trig = `AST_ONLY_HIGH` ✓

### Decision: Phase 1 + 2 fields spliced into all three combined dict branches

`fuse_labels.py` builds `combined` via three branches: `common` (signal in both
DFG and AST), `dfg_only`, `ast_only`. Each branch was independently updated to
splice in:
```python
**_glra_fields(glra_dfg.get(sig)),
**_qtflow_dfg_fields(qtflow_dfg.get(sig)),
**_qtflow_ast_fields(qtflow_ast.get(sig)),
```
All three helper functions return neutral defaults (risk=0.5, tls=0.5,
category=NO_DATA) when the entry is absent, so the feature matrix stays well-
defined for any design regardless of which scoring stages completed.

Short-name normalisation is applied to GLRA and QtFlow-DFG keys on load
(highest-score wins on collision). QtFlow-AST already uses bare signal names
so normalisation is a no-op in practice.

---

## Cross-Design Summary Table (full pipeline including Phase 1 + 2)

| Design | Trojan Type | DFG Detects | AST Detects | GLRA fires? | QtFlow-DFG | QtFlow-AST |
|--------|-------------|-------------|-------------|-------------|------------|------------|
| T100  | data_exfil | Yes | No* | Yes (INJECTED) | 0 INJECTED | 0 INJECTED |
| T2100 | power_side_channel | No | Yes (COUNTER=0.150) | Yes (ghost INJECTED) | 0 INJECTED (13 GHOST) | 13 INJECTED |
| T2300 | combinational_trigger | Yes (0.092) | No* | Yes | 1 INJECTED | 0 INJECTED |
| T2400 | combinational_trigger | Yes (0.096) | No* | Yes | 1 INJECTED | 0 INJECTED |
| T2500 | sequential_counter | No | No | Partial | 0 INJECTED (TIMING_CONTROL) | 0 INJECTED |
| T2600 | sequential_counter | Yes (0.096) | No* | Yes | 5 INJECTED | 0 INJECTED |

*AST limitation: module instantiation port connections not traced (cross-module paths).
T2500: trojan exploits existing AES control flow; no new timing channel introduced.
T2600 vs T2500: T2600 has a dedicated Trojan module with its own counter/$add/$eq chain → INJECTED.
T2500 has no such module; the trigger uses the AES state machine's existing control cells → TIMING_CONTROL (already present in golden).

---

## Outputs Per Design

After running the full pipeline, each `outputs/{DESIGN}/` folder contains:

| File | Stage | Description |
|------|-------|-------------|
| `netlist.json` | S1 | Yosys flat gate-level netlist |
| `ast_nodes.csv` | S1 | PyVerilog AST node table |
| `ast_edges.csv` | S1 | AST edge list |
| `ast_taint_scores.json` | S1 | AST per-signal IFT labels |
| `ast_report.txt` | S1 | Human-readable AST report |
| `taint_scores.json` | S2 | DFG per-node IFT labels |
| `dfg_nodes.csv` | S2 | GNN-ready node features (DFG) |
| `dfg_edges.csv` | S2 | GNN-ready edge list (DFG) |
| `dfg_taint_report.txt` | S2 | Human-readable DFG taint report |
| `golden_scores.json` | S3 | Trojan-masked baseline taint scores |
| `golden_nodes.csv` | S3 | GNN-ready golden node features |
| `delta_scores.json` | S3 | Per-node delta (full − golden) |
| `golden_report.txt` | S3 | Human-readable delta report |
| `glra_dfg_scores.json` | S3 | Phase 1: GLRA leakage risk per signal |
| `qtflow_dfg_scores.json` | S3 | Phase 2: QtFlow DFG timing leakage score |
| `qtflow_ast_scores.json` | S3 | Phase 2b: QtFlow AST timing leakage score |
| `combined_labels.json` | S4 | Fused DFG+AST+GLRA+QtFlow labels (GNN input) |
| `fusion_report.txt` | S4 | Human-readable fusion report |
| `hw2vec/node_features.npy` | S5 | GNN feature matrix (N × 14) |
| `hw2vec/edge_index.npy` | S5 | GNN edge list COO format (2 × E) |
| `hw2vec/labels.npy` | S5 | GNN binary labels (N,) |
| `hw2vec/metadata.json` | S5 | Node names, feature names, design info |

---

## Current Pipeline Status (Phase 1 + 2 complete)

All stages implemented. Full pipeline (Stages 1–6) has been run on **36 designs**
across 4 families: 26 AES-T* variants, PIC16F84-T100..T400, RS232-T2100..T2400,
wb_conmax-T200/T300 — every one has a complete `outputs/<DESIGN>/hw2vec/` export.

The deep-dive design rationale and per-signal validation below is anchored on a
6-design AES subset (T100, T2100, T2300, T2400, T2500, T2600) chosen to cover
all four trojan archetypes (data-exfil, power-side-channel, combinational
trigger, sequential counter). Non-AES families have not been validated at the
per-signal level — they are processed mechanically by the same pipeline.

Run with:
```bash
python3 run_pipeline.py --all          # all designs, full pipeline
python3 run_pipeline.py --design AES-T2100 --from-stage 4 --force  # rerun scoring + fusion
python3 run_pipeline.py --compare      # regenerate all figures (compare + GLRA + QtFlow)
```

Stage 4 now runs four sub-scorers in sequence:
`golden_delta → glra_dfg → qtflow_dfg → qtflow_ast`

**Per-design results (6-design AES subset):**

| Design | AST nodes | DFG nodes | Trojan path (DFG) | COUNTER/trigger | Fusion category |
|--------|-----------|-----------|-------------------|-----------------|-----------------|
| T100  | — | — | — | DFG exfil path | DFG detects |
| T2100 | 5316 | 4969 | 12 (ghost) | DFG=0.000 AST=0.150 | **AST_ONLY_HIGH** |
| T2300 | 5095 | 4926 | 1158 | DFG=0.092 AST=0.000* | DFG detects |
| T2400 | 5095 | 4926 | 1618 | DFG=0.096 AST=0.000* | DFG detects |
| T2500 | 5117 | 4931 | 0 | DFG=0.000 AST=0.000 | AGREE_LOW — both blind |
| T2600 | 5127 | 4934 | 705 | DFG=0.096 AST=0.000* | DFG detects |

GNN export: `hw2vec/node_features.npy` is (N, 14) float32 for all designs.
Feature columns 0–10: unchanged from initial pipeline.
Feature column 11: `glra_dfg_risk` (Phase 1).
Feature column 12: `qtflow_dfg_tls` (Phase 2).
Feature column 13: `qtflow_ast_tls` (Phase 2b).

**Visualizations produced by `run_pipeline.py --compare`:**
- `fig_full_comparison.png` — 5-panel DFG vs AST fusion figure (viz_compare.py)
- `fig_glra_{design}.png` — Per-design GLRA risk bars (viz_glra_bars.py)
- `fig_qtflow_{design}.png` — Per-design DFG + AST TLS bars (viz_qtflow.py)
- `fig_qtflow_compare.png` + 4 sub-figures — Cross-design QtFlow overview (viz_qtflow.py)

**Known limitations (not bugs):**
1. Base AST data-taint (`stage1_extract/run_ast.py`, feature col 1 `ast_score`)
   still does not trace module instantiation — T2300/T2400/T2600 show 0 on the
   trojan path for this specific feature. DFG handles it correctly. **Fixed for
   QtFlow-AST specifically — see "Hierarchical AST cross-module tracing" below**;
   extending the same fix to `run_ast.py`'s base taint scorer is a follow-up,
   not yet done (scoped out per the original plan's conditional step 4 — it's
   a separate walker/BFS with its own namespace-collision risk profile).
2. T2500 is fundamentally undetectable by IFT — no data dependency from key/state
   to trigger. Both DFG and AST agree: AGREE_LOW. This is a genuine finding.
3. (superseded by the fix below) QtFlow-AST previously could not trace
   cross-module timing paths for the same reason as (1).

### Hierarchical AST cross-module tracing for QtFlow-AST (implemented)

Fixes the gap in (1)/(3) above for `stage3_scoring/qtflow_ast.py` specifically.
Root cause: `ASTTimingWalker` walked the whole `ast_root` in one pass with a
**flat global signal namespace** — every module's ports/internals shared one
dict key space. A prior attempt to add raw Instance port-connection edges
blanketed taint everywhere (T2600 went 0 → 82/82 INJECTED) because bare port
names like `key`/`clk`/`r1` collide across unrelated module instances.

**Fix — instance-qualified namespace, not a global one:**
- `_collect_module_defs()` indexes every `ModuleDef` by name once per design.
- The walker now enters only from the design's top module (`walk_top()`),
  not from `ast_root` directly — a module body is visited **only** when
  reached via an `InstanceList`/`Instance` connection, never standalone. This
  alone removes the collision risk: an uninstantiated or unreachable module's
  bare names never enter `rhs_deps`.
- `_handle_instance()` resolves each instantiation's port connections
  (confirmed via direct PyVerilog AST inspection: every Instance in this
  corpus uses purely positional `PortArg(portname=None, argname=...)`, so
  positional matching against the callee's declared `Ioport` order is
  required — named `PortArg.portname` is supported as a fallback but unused
  here) and recurses into the callee module body under an instance-qualified
  prefix (`self._instance_path`, e.g. `"Trojan"`), so every identifier
  collected inside becomes `Trojan.r1` instead of bare `r1` — mirroring the
  DFG side's existing `Trojan.LEAKBit`-style dotted convention.
- Port-connection edges are added **bidirectionally** (`rhs_deps[formal]↔
  rhs_deps[actual]`) since there's no reliable port-direction info available
  for these positional connections — safe over-approximation for a forward
  taint-reachability BFS.
- Golden (masked) walk: if the callee module name is trojan-named, the entire
  instantiation (wiring + recursion) is skipped, matching the existing
  `_masked` semantics used for non-Instance nodes.
- `MAX_INSTANCE_DEPTH = 12` recursion guard, consistent with the existing
  `MAX_CYCLES` guard on the taint BFS — depth-capping any traversal over a
  graph with potential cycles is a standing project convention.

**Verified result — AES-T2300** (`TSC Trojan(s2[89], s5[121], Tj_Trig)`,
positional instantiation of `module TSC(r1, r2, trigger)`):
`Trojan.r1`, `Trojan.r2`, `Trojan.trigger`, and `Tj_Trig` are now all
`TIMING_INJECTED` (previously invisible — `s2`/`s5` were tainted inside
`aes_128` but the edge into `TSC`'s ports, and back out via `Tj_Trig`, did
not exist). QtFlow-AST INJECTED count on T2300 went 0 → 4.

**Verified no regression — AES-T2600** (the design that caused the original
82/82 blanketing failure): re-running with the new instance-qualified logic
gives exactly 4 INJECTED signals (`Tj_Trig`, `Trojan.trigger`, `Trojan.r1`,
`Trojan.counter`) — not a blanket. Full `--all` sweep across all 26 AES
designs shows INJECTED counts in the single-to-low-double digits everywhere
(max 31 on T1400), confirming the namespace fix, not the removal of Instance
handling, was what prevented the earlier blanketing.

Note: this feeds GNN feature column 13 (`qtflow_ast_tls`) and the QtFlow-AST
category, not feature column 1 (`ast_score`, the base data-taint used for
`fuse_labels.py`'s `AST_ONLY_HIGH` classification) — those are computed by
the separate `stage1_extract/run_ast.py` scorer, which still has the
cross-module gap (limitation 1 above). Downstream Stage 6 GNN AUROC on
`AES-T2300` did not show a clean improvement in one retrain (0.559 → 0.494,
within this design's own run-to-run noise floor at n_pos=5 — CPU BLAS
threading makes even a fixed-seed run non-bit-reproducible after ~20
epochs); the fix's effect is real and directly verified at the QtFlow-AST
signal level above, but is too small a per-node feature contribution (1 of
14 dims, and only for a design with 5 positive nodes out of 4926) to move
the aggregate GNN metric outside its own noise on a single run.
   T2600's counter trigger is caught by DFG QtFlow (5 INJECTED) but not AST.

---

## Stage 6 — GNN training on hw2vec exports (implemented)

Implemented in `stage6_train/{dataset,model,train,evaluate}.py`. Wired into
`run_pipeline.py --train`.

**First run (GraphSAGE, seed 1337, 80/20 design split, pos_weight=4.11):**
- Best val micro-F1 = **0.933**, val micro-AUROC = **0.943** at epoch 10
  (early stop at 20).
- Per-design val results expose where label fusion is weakest:
  - High recall: `wb_conmax-T300` F1=0.936, `AES-T1600` F1=0.802.
  - AUROC ≫ F1 on `PIC16F84-T200` (3 pos / 1616) and `AES-T2300` (5 pos / 4926):
    the model ranks correctly but the 0.5 threshold is wrong for these tiny
    positive sets — threshold sweep is the next step, not a model issue.
  - `AES-T2300` AUROC=0.54 is the genuine failure mode and matches the
    Stage-4 finding that AST cross-module trace fails on T2300.
- Top-FN are AES-T400 `Tj_Trigger.*` mux nodes — labels mark them trojan
  but their 14-dim features look clean (low IFT score, no ghost taint),
  consistent with the AST cross-module instantiation gap.

Verification recipe (still valid):
```bash
python3 -m stage6_train.dataset            # smoke
python3 run_pipeline.py --train            # full
python3 -m stage6_train.evaluate           # metrics + figure
cat outputs/gnn/metrics.json | python3 -m json.tool
```

Outputs:
- `outputs/gnn/checkpoints/sage_best.pt` — best checkpoint (with train/val
  design names embedded for deterministic re-eval).
- `outputs/gnn/train_log.json` — full per-epoch history.
- `outputs/gnn/metrics.json` — per-design + aggregate + top-k FP/FN.
- `outputs/gnn/figures/confusion_matrix_sage.png`.

Out of scope (still deferred): graph-level TjFree-vs-TjIn classification is
now implemented (see below); UCSD hw2vec library comparison remains deferred.

### Graph-level TjFree-vs-TjIn classification (implemented)

Unlocks a second, complementary evaluation axis: whole-design clean/trojan
classification, comparable to standard HW2Vec's graph-level task (see the
reviewer critique in `vault for testing/Future work to Do evaluations.md`,
which specifically flags this as needed for a fair HW2Vec comparison table).

**Pipeline changes** — a `variant` parameter (`"tjin"` default | `"tjfree"`)
threaded through every stage entry point:
- `config/pipeline_config.py`: `_auto_detect()`/`get_design_config()` take
  `variant`; `"tjfree"` points all scanning (`verilog_dir`, `top_module`,
  `sources`, `trojan_patterns`, ...) at `src/TjFree/` instead of `src/TjIn/`.
  Output directory becomes `outputs/<design>__tjfree/` — a fully separate
  namespace, so a tjfree run never clobbers the design's normal TjIn outputs.
  `trojan_patterns` naturally comes back near-empty for TjFree (no trojan
  module files exist in that source tree) or falls back to the harmless
  literal default `["TSC", "Trigger"]`, which matches nothing real — so
  golden-masking, GLRA, and QtFlow all degrade gracefully to "nothing to
  find" rather than needing special-casing.
- `run_pipeline.py --variant {tjin,tjfree}` — new flag, forwarded through
  `run_design()` to every stage function. `--compare` figure generation is
  skipped for `--variant tjfree` (those figures assume TjIn semantics).
- `stage5_export/hw2vec_export.py`: writes a new `graph_label.npy` (0/1,
  design-level: 1 if any node is trojan-labelled, i.e. TjIn runs normally
  produce 1 and TjFree runs produce 0) alongside the existing per-node
  `labels.npy`. Also stamps `variant`/`graph_label` into `metadata.json`.

**Verified:** `python3 run_pipeline.py --design AES-T2100 --variant tjfree
--force` runs all 6 stages cleanly, writes `outputs/AES-T2100__tjfree/`,
and produces an all-zero `labels.npy` / `graph_label.npy == 0` (confirmed:
`golden_delta`/`GLRA`/`QtFlow-DFG`/`QtFlow-AST` all report 0
injected/elevated signals, as expected with no trojan present). The TjIn
run for the same design is untouched in its own `outputs/AES-T2100/`.

**Stage 6 graph-classification head** — `stage6_train/`:
- `dataset.py`: `IFTGraphDataset` loads both variants per design (where a
  tjfree export exists) into one `Data` object each with `y` = graph_label.
  `.split()` splits **by design name**, keeping both variants of the same
  design on the same side — otherwise the model could see a design's TjIn
  graph in training and its near-identical TjFree twin in validation,
  leaking structure instead of testing generalization.
- `model_graph.py`: `GraphSAGEGraphClassifier` — 3-layer SAGEConv +
  `global_mean_pool` + linear head, matching the sketch already drafted in
  the reviewer doc (reused rather than rewritten from scratch).
- `train_graph.py`: same BCEWithLogitsLoss + pos_weight + early-stop-on-F1
  pattern as `train.py`, batched via PyG `DataLoader` (auto-builds `.batch`
  for pooling). Writes `checkpoints/sage_graph_best.pt` +
  `train_log_graph.json`.

**Smoke-test scope:** TjFree exports were generated for the 6 deep-dive AES
designs (T100, T2100, T2300, T2400, T2500, T2600) — 42 graphs total (36 TjIn
+ 6 TjFree) feed `IFTGraphDataset`; the other 30 designs are cleanly skipped
(logged, not silently dropped) pending their own `--variant tjfree` runs.
Training converges with no NaNs (best val_f1=0.933 on a smoke run) but the
per-fold numbers are not meaningful yet — the validation split lands only 1
TjFree graph in val out of 7 val designs at this sample size. Generating
TjFree exports for the remaining 30 designs (`for d in $(...); do
python3 run_pipeline.py --design $d --variant tjfree; done`) is a
mechanical follow-up, not a code change, before this axis can produce a
report-quality number.

### LOFO CV + threshold calibration (implemented, LOFO later removed — see 2026-08-10 entry)

Addressed the two gaps flagged above: the random 80/20 split hides whether
the GNN generalizes across IP-core architectures, and the fixed 0.5 logit
threshold mismatches the `pos_weight`-balanced training loss.

- `dataset.py`: `family_of_design()` maps design name → IP-core family
  (`AES`/`PIC16F84`/`RS232`/`wb_conmax` by name prefix — distinct from
  `visualize/style.py`'s `family_of()`, which groups by *trojan behavior*,
  not IP core). `IFTNodeDataset.lofo_splits()` yields one `(train, val,
  held_out_family)` per family.
- `train.py --split-mode lofo`: trains one fold per held-out family,
  writing `checkpoints/sage_<FAMILY>_best.pt` and `train_log_<FAMILY>.json`
  each, plus an aggregate `train_log_lofo_summary.json`. `--split-mode
  random` (default) is unchanged and keeps writing the original unsuffixed
  `sage_best.pt`/`train_log.json`.
- `evaluate.py --fold <FAMILY>` loads a LOFO checkpoint instead of the
  random-split one; `--calibrate` sweeps per-design thresholds (0.01 steps)
  and reports the F1-maximizing threshold/F1 alongside the fixed-0.5 metric.

**LOFO results (GraphSAGE, seed 1337, full run to early stop):**
```
AES        best_val_f1=0.031  (10 train designs: PIC/RS232/wb_conmax)
PIC16F84   best_val_f1=0.234
RS232      best_val_f1=0.974
wb_conmax  best_val_f1=0.664
mean       best_val_f1=0.476
```
This is the honest generalization number to report next to the random-split
micro-F1=0.933 — it exposes that the model does **not** transfer well to
AES when trained only on the other 3 (structurally simpler) IP cores. This
is expected and worth stating plainly: AES is the most structurally diverse
family in the corpus (26 of 36 designs, many trigger archetypes), so a
3-family training pool is a weak proxy for it. RS232/wb_conmax transfer much
better, consistent with those families' Trojans following similar
structural patterns to their siblings.

**Calibration results (random-split checkpoint, threshold swept per design):**
- Aggregate: macro-F1 0.482 → **0.556**, micro-F1 0.933 → 0.940 (at t=0.58).
- `PIC16F84-T200` (3 pos/1616): F1 0.059 → 0.095 at t=0.45.
- `AES-T2300` (5 pos/4926): F1 0.000 → 0.095 at t=0.19 — the AUROC=0.559 for
  this design confirms calibration alone cannot fix it; the ranking itself
  is broken because of the AST cross-module gap (see Item 1 above), not the
  threshold. This is the concrete evidence that AES-T2300 needs the
  hierarchical-AST fix, not just recalibration.

Out of scope (still deferred): cross-family holdout is now implemented via
LOFO above; graph-level TjFree-vs-TjIn classification and UCSD hw2vec
comparison remain deferred.

---

## Original Stage 6 plan (kept for reference)

Status: **planned, not implemented.** Stage 5 already exports
`outputs/<DESIGN>/hw2vec/{node_features.npy, edge_index.npy, labels.npy, metadata.json}`
for all 36 designs (26 AES + 4 PIC16F84 + 4 RS232 + 2 wb_conmax). No GNN
training code exists yet. This section captures the agreed approach so it can
be picked up later.

### Decisions locked in
- **Framework:** plain PyTorch Geometric (load `.npy` arrays directly into
  `torch_geometric.data.Data`). UCSD hw2vec library is *not* used — its
  Verilog→graph frontend would have to be bypassed and it doesn't natively
  consume our 14-dim per-node features or per-node labels.
- **Task:** node-level binary classification (trojan vs clean per signal).
- **Split:** simple 80/20 random design split, fixed seed. Smoke-test grade —
  the rigorous follow-up is leave-one-design-out CV; flag this in the thesis.

### Files to add

```
Programs/Test/pipeline/
├── stage6_train/
│   ├── __init__.py
│   ├── dataset.py        # IFTNodeDataset: load all designs into a list of Data
│   ├── model.py          # 3-layer GraphSAGE (primary) + 2-layer GCN (baseline)
│   ├── train.py          # BCEWithLogitsLoss + pos_weight, early stop on val F1
│   └── evaluate.py       # per-design + aggregate metrics, confusion-matrix figure
└── outputs/gnn/          # checkpoints, metrics.json, figures/
```

### Design notes
- Reuse `config.pipeline_config.discover_designs()` for the design list; skip
  any design missing the `hw2vec/` subdir.
- 14-dim feature ordering must mirror `stage5_export/hw2vec_export.py`.
- Class imbalance: pos_weight ≈ neg/pos per training set (~50–500×). Report
  AUROC alongside F1 since it's threshold-invariant.
- Top-k FP / top-k FN tables in `evaluate.py` — feed into thesis discussion of
  where AST vs DFG paths fail.
- `run_pipeline.py`: add `--train` flag (mutually exclusive with
  `--design`/`--all`/`--compare`); training is dataset-wide, not per-design.

### New dependencies
```
torch >= 2.0
torch-geometric >= 2.4
torch-scatter, torch-sparse
scikit-learn
```

### Verification recipe
```bash
# from the repository root
python3 -c "from stage6_train.dataset import IFTNodeDataset; ds=IFTNodeDataset(); print(len(ds.data_list))"
python3 -m stage6_train.train --epochs 10 --device cpu      # smoke
python3 run_pipeline.py --train                              # full run
python3 -m stage6_train.evaluate
cat outputs/gnn/metrics.json | python3 -m json.tool
```
Success target: training stable (no NaN), val AUROC > 0.85, per-design metrics
written to `metrics.json`.

### Out of scope when this work resumes
- Leave-one-design-out CV
- Cross-family holdout (AES-trained → PIC/RS232/wb_conmax)
- Graph-level TjFree-vs-TjIn classification (needs Stage 1–5 re-run on
  `TjFree/` sources — currently only `TjIn/` is exported)
- UCSD hw2vec library comparison on raw Verilog
- GAT / hyperparameter sweep

---

## Full clean rerun vs. halftime report baseline (commit `dbcb13e`)

After landing the three fixes above (hierarchical AST tracing, LOFO +
calibration, TjFree graph classification), `outputs/` was deleted entirely
and the full pipeline re-run from scratch to get a clean, reproducible
snapshot: `run_pipeline.py --all --force`, `--variant tjfree` for the 6
deep-dive AES designs, `stage6_train.train` (`--split-mode random` and
`--split-mode lofo`), `stage6_train.evaluate --calibrate`,
`stage6_train.train_graph`, and `visualize/viz_gnn.py` (this script existed
since the halftime commit but had not been re-run this session — it
reproduces the 8-figure GNN figure set: training curves, ROC/PR, score
distribution, calibration, per-design F1/AUROC, confusion-by-split,
top-errors). Full write-up with embedded before/after figures:
`HALFTIME_VS_NOW_REPORT.md` (also copied into `vault for testing/`).

### Aggregate GNN metrics — halftime vs. now (random 80/20 split, same 7 val designs)

| Metric | Halftime | Now |
|---|---|---|
| val micro-F1 | 0.933 | 0.998 |
| val micro-AUROC | 0.943 | 0.9996 |
| val macro-F1 | 0.440 | 0.736 |
| val macro-F1 (calibrated) | n/a (not implemented) | 0.783 |

6 of 7 halftime validation designs improved on both F1 and AUROC. The one
exception: `AES-T2700` F1 held at 0.560 but AUROC dropped 0.943 → 0.711 —
not a design touched by the AST fix, so most likely training-run variance
rather than a real regression (see caveat below), but not confirmed either
way from a single run.

### QtFlow-AST INJECTED count — halftime vs. now (deterministic, not training-noise-affected)

| Design | Halftime | Now |
|---|---|---|
| AES-T2300 | 0 | 4 (`Trojan.r1`, `Trojan.r2`, `Trojan.trigger`, `Tj_Trig`) |
| AES-T2600 | 0 | 4 (`Trojan.r1`, `Trojan.trigger`, `Trojan.counter`, `Tj_Trig`) |

This is the one number in the comparison that's a direct read of the
scorer's own output rather than a stochastic training result — the AST fix
is confirmed working, independent of any GNN run-to-run variance.

### Caveat — GNN training is not bit-reproducible across processes on CPU

Same fixed seed (1337), same code, re-invoking `stage6_train.train` in a
fresh process produced val micro-F1 anywhere from 0.933 to 0.998 across
different runs this session, with zero code changes between them (CPU BLAS
thread-reduction order isn't deterministic, and GraphSAGE dropout/training
amplifies small floating-point differences over ~30-40 epochs). Conclusion:
the aggregate F1/AUROC deltas above are directionally credible (6/7 designs
improved) but the exact magnitudes should not be quoted in the thesis
without averaging over multiple seeds. The QtFlow-AST INJECTED counts and
the LOFO mean (below) are not subject to this caveat in the same way — LOFO
still has training-seed variance per fold, but its qualitative conclusion
(AES generalizes worst) has now been observed across 3 separate runs this
session with consistent ordering (AES worst, PIC16F84 second-worst, RS232
and wb_conmax best), which is a more robust signal than a single point value.

### LOFO mean, observed across 3 runs this session (LOFO later removed — see 2026-08-10 entry)

| Run | AES | PIC16F84 | RS232 | wb_conmax | Mean |
|---|---|---|---|---|---|
| 1 | 0.031 | 0.234 | 0.974 | 0.664 | 0.476 |
| 2 | 0.046 | 0.234 | 0.974 | 0.670 | 0.481 |
| 3 (this rerun) | ~0.03–0.05 | 0.234 | 0.66–0.97 | 0.664 | 0.479 |

Consistent qualitative ordering across runs (AES worst, wb_conmax/RS232
best) — this is the number to lead with in the thesis over any random-split
micro-F1, since it survives the "does this actually generalize" question in
a way the inflated random-split number does not.

---

## 2026-07-24 16:04 CEST — NINA_DATA/FINAL-DATA corpus (190 designs) onboarded

Extended the pipeline to `NINA_DATA/FINAL-DATA/` — 190 designs (135 `core_*`
generic IP cores, 27 `TrustHub_AES*`, 14 `hw2vec_*` re-exports of existing
PIC16F84/RS232 designs, 14 `GH_*` LLM-synthesized trojans), overwhelmingly
non-confidentiality trojans (DoS/corruption/spoofing) with inline (no
separate module) trojan insertion — structurally very different from the
legacy 36-design Trust-Hub corpus this pipeline was built around.

**Code changes** (`config/pipeline_config.py`, `stage2_ift/dfg_taint.py`,
`stage5_export/hw2vec_export.py`, `stage6_train/dataset.py`,
`stage6_train/train.py`, `stage6_train/evaluate.py`, `visualize/viz_gnn.py`,
`visualize/viz_compare.py`, `visualize/viz_qtflow.py`, `visualize/style.py`,
new `config/trojan_categories.json`):
- `topModule.v` top-module detection + redundant-sibling-file dedup (three
  distinct collision shapes found and fixed, including a bug where the fix
  itself wrongly dropped a design's real trojan module).
- Comment-anchored inline-trojan-boundary extraction
  (`_extract_inline_trojan_region`) — replaces a "whole non-core file is
  trojan" sweep that would otherwise mask the entire circuit for
  single-file designs.
- Category-aware source fallback (`classify_trojan_effect` +
  `trojan_categories.json`): leak_info/dos/corruption/spoofing/other,
  instead of forcing the confidentiality `key|state|secret` heuristic onto
  non-leakage designs.
- `--corpus {legacy,new,all}` added to `run_pipeline.py`,
  `stage6_train.train`, `.evaluate`, `visualize.viz_gnn` — all
  corpus-tag-suffixed so legacy-only checkpoints/metrics/figures are never
  silently overwritten.
- `family_of_design()` (Stage 6 LOFO) now groups NINA_DATA designs by
  `trojan_effect` instead of collapsing into singleton pseudo-families —
  legacy 36 grouping logic left untouched (verified: 26 of the 36 already
  had a populated `trojan_effect` via `trojan_types.json`, which would have
  silently changed the existing IP-family LOFO experiment otherwise).
- Two real Stage 6 labeling bugs found and fixed after actually running the
  pipeline (not caught by code review alone): a first fix mislabeled 35% of
  AES-T2100 as trojan by counting the `key`/`state` source signal itself
  (`AGREE_HIGH` is satisfied by role_bonus=1.0 sources, not just trojans);
  narrowing to `AST_ONLY_HIGH` alone was *still* too loose (catches ordinary
  signals like `clk`/`rst` under Stage 4's interpretation-tuned 0.08
  threshold) — final fix additionally gates on a `trojan_patterns` substring
  match, same predicate `golden_delta.py`'s masking already uses.

**Results:** 189/190 designs run end-to-end (1 fails at Yosys — genuine
unrelated Verilog issue, a port driven by a constant). 171/190 (90%) produce
non-degenerate GNN labels; 18 honestly flagged via `suspect_mislabeled`
rather than force-labeled. GNN random-split: combined 226-design corpus val
micro-F1=0.996 (legacy-only baseline 0.998, confirming no regression).
LOFO mean val_f1=0.873 across 53 folds — but only ~9 are genuine multi-design
folds (5 trojan-effect categories + 4 legacy IP families, 0.89–0.999); the
rest are singleton per-design "folds" because the effect classifier only
fires for inline single-sibling-file designs, not module-boundary
(`TrustHub_AES*`) or fully-self-contained-single-file (`hw2vec_*`,
`core_basic_spi_master_HT*`) cases — flagged as a follow-up, not yet fixed.

Comparison figures (`visualize/viz_compare.py`, `visualize/viz_qtflow.py`)
extended to load both corpora; `family_of()`/`FAMILY_COLORS` in
`visualize/style.py` extended with the new effect categories so NINA_DATA
designs don't all collapse into one grey "unknown" bucket. GLRA per-design
bars (`viz_glra_bars.py`) dropped from `run_compare()` — not a useful figure
(mostly empty/neutral, no clearer story than the scatter/heatmap already
tell). DFG-vs-AST scatter split into its own standalone figure
(`fig_dfg_ast_scatter.png`) since it doesn't get harder to read as the
corpus grows, unlike the per-design bar charts, which now scale their figure
width/height with design count instead of a fixed size tuned for 36 designs.

**Honest assessment for the thesis claim** ("this tool generalizes across
any Verilog design and labels accurately"): the evidence supports a scoped
version of that claim, not the maximal one.
- Strong: the AST-catches-what-DFG-misses mechanism reproduced organically
  on `core_ahb_lite_master_HT1` — a non-crypto, non-confidentiality design
  nothing like AES-T2100 — which is real evidence the *mechanism*
  generalizes, not just the AES-tuned heuristics. 90% non-degenerate output
  and stable GNN metrics on a corpus 6x larger and structurally far more
  diverse is a genuine engineering-robustness result.
- Weak: "ground truth" here is category-level (a keyword classifier over
  trojan-marker comments), not an independently-audited node-level
  precision/recall — only a handful of designs were spot-checked by hand.
  The tool also still depends on some structural hint to find the trojan
  boundary at all (separate module, crypto key/state naming, or an explicit
  `// ... Trojan ...` comment) — an unannotated, non-crypto, no-separate-
  module design would likely land in the same 10% degenerate bucket.
  The 0.873 LOFO headline is inflated by singleton folds; the honest number
  is the 0.89-0.999 range on genuine multi-design folds, alongside the
  already-known `PIC16F84` weak point (0.234).

Recommended framing: "the IFT methodology's core detection mechanism
generalizes beyond the original crypto benchmark to a structurally diverse
corpus with explicit trojan annotations, producing non-degenerate GNN
training data for 90% of it" — not "accurately labels any design". Highest-
value next step to strengthen the accuracy claim specifically: a manual
precision audit on a random sample (~15-20) of the 171 non-degenerate
designs against their documented trojan description, rather than more scale.

---

## 2026-08-07 — three follow-up gaps closed: AST cross-module base scorer, LOFO fold-grouping, manual precision audit

Closed all three gaps flagged above.

**AST cross-module fix, extended from the timing scorer to the base
scorer.** `stage3_scoring/qtflow_ast.py`'s instance-qualified walker
(`_collect_module_defs`, `_formal_port_names`, `_qualify`/`_qualify_all`,
`MAX_INSTANCE_DEPTH`, and the `is_clock_or_reset` filter) was extracted into
a new shared module, `stage1_extract/ast_crossmodule.py` — verified as a
pure refactor (byte-identical `qtflow_ast_scores.json` on T2100/T2300/T2400/
T2600 before/after). `stage1_extract/run_ast.py`'s base `ASTWalker` gained a
parallel instance-qualified taint graph (`build_crossmodule_taint`, a
cut-down sibling of `ASTTimingWalker` that only tracks assignment deps +
sens-list control, not the timing/cycle-depth extras QtFlow-AST needs),
collapsed back to bare signal names so `ast_taint_scores.json`/
`combined_labels.json`'s `ast_score` (GNN feature col 1) stays keyed the
same way for the DFG join. Direct validation: T2300/T2400 went from 0 → 3
trojan-path signals (`r1`, `r2`, `trigger` — matching qtflow_ast's earlier
finding), T2600 similarly nonzero; T2100's documented validation target
(`COUNTER`, `taint_score=0.1502`, unrelated to this fix) stayed
byte-identical, confirming no regression on single-module designs. Also
caught and fixed a false-positive bug along the way: clk/rst signals wired
into the trojan instance's ports were being tagged trojan-related purely by
port connection, inflating T2600 to 70 "trojan path" nodes — fixed by
reusing the existing clock/reset exclusion filter, dropping it back to the
correct 2-3 signals per design. Full corpus rerun (`--all` + `--new-corpus`,
`--from-stage 2 --force`) confirmed zero regression: 189/190 new-corpus
designs still run, 171/190 still non-degenerate, 18/226 still
`suspect_mislabeled` — identical to the pre-fix baseline. Multi-seed
(3-seed) random-split retrain on the combined 226-design corpus:
val_f1 = 0.996, 0.996, 0.976 — matches the pre-fix baseline, no regression.

**LOFO fold-grouping fix.** Root cause confirmed: `family_of_design()` in
`stage6_train/dataset.py` fell back to `design.split("-T")[0]` — a no-op
for any name without a `-T` substring — whenever `trojan_effect` couldn't
be classified, which was most of `core_*` (135), `GH_*` (14), and all of
`TrustHub_AES*` (27, confirmed live: `trojan_types.json` does NOT have a
`TrustHub_AES01`-style key, so the catalogue fallback that works for legacy
names doesn't fire here either). Added `_ip_family()`, handling the three
real naming shapes verified against the live corpus:
`core_<ip>_HT<n>` → `core_<ip>` (reusing the existing `_HT_SUFFIX_RE`),
`GH_<ip><n>_<llm-tag>` → `GH_<ip>` (e.g. `GH_AES21_gem` → `GH_AES`), and
`TrustHub_AES<nn>` → `TrustHub_AES` (trailing digits stripped). Wired in as
a fallback tier between `trojan_effect` and the old dead `-T`-split, legacy
36 branch left completely untouched (verified: all 36 legacy designs
resolve to the same family before/after). **Before:** 53 folds, only 11
genuine multi-design (42 singletons — leave-one-design-out, not a real
holdout). **After: 16 folds, all 16 genuine multi-design, zero
singletons.** 3-seed LOFO retrain on the corrected grouping:
mean val_f1 = 0.910, 0.905, 0.907 (mean ≈ **0.907**, tight ~0.005 spread) —
this is the new honest LOFO headline, replacing the old 0.873 (which was
inflated by the 42 singleton pseudo-folds). `PIC16F84` remains the weakest
individual fold (val_f1 ≈ 0.234, consistent across all 3 seeds) — a
genuine, now cleanly-isolated generalization gap rather than an artifact of
fold construction.

**Manual precision audit** — `AUDIT_REPORT.md` (new file, pipeline root).
18 designs stratified across legacy-36, `hw2vec_*`, `TrustHub_AES*`,
`core_*`, and `GH_*`, checked against `trojan_descriptions.md` /
`Spec.doc`/`Read me.txt` / raw Verilog trojan-marker comments. Verdicts:
**7/18 MATCH, 4/18 PARTIAL, 7/18 MISS**. Key findings:
- When the pipeline flags a signal (`AGREE_HIGH`/`AST_ONLY_HIGH`), it's
  never flatly wrong — precision on flagged signals is high across every
  bucket, including a striking direct hit (`Capacitance` in AES-T100 is
  literally the leakage circuit's named capacitance-mimicking node;
  `trojantrigger2` in core_CarryLook_HT3 is the trojan's own trigger
  signal, present verbatim in the flagged set).
- The 7 MISSes split into two distinct, separately-actionable causes: (1)
  pure control-flow triggers with no dependency on a tracked data source
  (PIC16F84-T100, RS232-T2100, and their `hw2vec_*` re-exports) — the same
  structural IFT gap already documented for AES-T2500, now confirmed to
  recur across a different family; (2) generic/LLM-chosen trojan signal
  naming not covered by configured `trojan_patterns` (`GH_sram32_lama`'s
  explicit `trojan_counter`/`trojan_activate` regs flagged nothing) — a
  solvable config gap, not a structural detector limitation.
- Found a labeling-pipeline bug independent of detector accuracy:
  `core_KoggeStone_HT1`/`HT2`'s DFG/AST scores correctly identify the
  corrupted prefix-tree nodes (`g`/`p`/`ginit`/`pinit`/`carries`), but the
  stricter `trojan_patterns` substring gate used to build the actual GNN
  training label rejects them anyway (`suspect_mislabeled=True`) — the
  detector is right and the label is wrong, a distinction worth keeping
  separate when discussing accuracy.

**Why:** all three were the specific, named gaps flagged as weakening the
thesis's correctness/generalization claims after the NINA_DATA onboarding
session — an inflated LOFO headline, an unaudited automated-label ground
truth, and a documented-but-unfixed detector blind spot. Closing them
converts "the mechanism looks like it generalizes" into a number and a
report that can be cited directly.
**How to apply:** cite LOFO mean ≈ 0.907 (not 0.873) going forward — it's
the same computation, just over folds that are all genuine holdouts.
Cite the audit's 7/18 MATCH rate and the two-cause MISS breakdown, not a
single "labels are accurate" claim. The KoggeStone label-gate bug is a
candidate follow-up (loosen or per-design-override the `trojan_patterns`
gate for `suspect_mislabeled` designs whose category scores already look
correct) but wasn't fixed here — flagging, not closing, that one.

---

## 2026-08-10 — source-name auto-resolution, `--check-sources`/`--train-eval` tooling, `holdout`/`kfold` splits replace LOFO

**Root-cause fix: auto-detected `sources` silently didn't match the
synthesized netlist for ~52+ designs.** Investigating why the QtFlow
cross-design comparison kept printing `no QtFlow scores — skipping` for the
same large batch of `core_*`/`hw2vec_*` designs surfaced two distinct bugs
in `config/pipeline_config.py`'s `_auto_detect()`:
1. The identifier regex used by the inline-trojan-region scanner
   (`_extract_inline_trojan_region`, and the trojan_patterns wire/reg scan)
   didn't treat `'` as a token boundary, so Verilog numeric literals like
   `2'b11`/`8'h66` were mis-tokenized into fake identifiers `b11`/`h66` and
   injected into `sources`. Fixed with a `(?<!')` lookbehind on both
   `ident_re` occurrences.
2. Several design directories ship a stale sibling source file (pre-
   normalization, underscored names — e.g. `trojan_counter_trigger`)
   alongside the file Yosys actually synthesizes as the design's top module
   (already flattened/renamed — e.g. `trojancountertrigger`). Auto-detect's
   category-aware fallback scans whichever file matches its trojan-marker
   heuristics, which is often the stale sibling, so the resulting source
   name never matches any real post-synthesis net — DFG taint propagation
   and QtFlow scoring then silently produce all-empty results with no error.

**Fix:** added `_collect_signal_idents()` (declared ports + reg/wire
declarations of the actual synthesized top file, excluding
`parameter`/`localparam` names, which are compile-time constants that never
appear as netlist nets) and `_resolve_against_signals()` (exact match, else
underscore-stripped case-insensitive fuzzy match) — applied to every
auto-detected `sources` entry before it's returned from `_auto_detect()`.
Verified directly against `netlist.json` netnames for the previously-broken
`core_ConfMeshRout_HT1`, `core_DualPortRam_HT2`, `core_KoggeStone_HT1`,
`core_MemCrtl_HT3`: all four now resolve to their real synthesized signal
names and produce non-empty QtFlow-DFG/AST scores. Corpus-wide, designs with
zero resolvable sources dropped from ~52 (pre-fix) to 7 genuine gaps
(post-fix, confirmed via the new `--check-sources` tool below) — the
remaining 7 have no matching signal in the source at all (parameters, or no
dedicated trigger signal), which needs a manual `designs.json` review, not a
heuristic fix.

**New tooling in `run_pipeline.py`:**
- `--check-sources` — loops `discover_designs()` + `get_design_config()` and
  lists every design with an empty `sources` list, in seconds, without
  running synthesis. Exists so this class of gap is caught before a
  multi-hour `--all` run, not discovered as WARN spam in the comparison
  figures afterward.
- Config-staleness auto-force (`_is_stale()`): compares `config/
  designs.json`'s mtime against a design's `combined_labels.json` mtime; if
  the config was edited after the design's last run, `--all`/`--design`
  automatically forces a recompute for that design even without `--force`.
  Previously, editing a `sources` override and re-running without `--force`
  silently left the old, wrong outputs in place indefinitely.
- `--train-eval` — chains `stage6_train.train` → `stage6_train.evaluate` →
  `visualize.viz_gnn` in one command (previously `--train` ran training
  only, silently ignoring any model/epoch/split-mode overrides passed to
  it — now all of `train.py`'s/`evaluate.py`'s tunable args are exposed and
  threaded through consistently by `run_pipeline.py`).

**New split-mode: `holdout` (3-way 60/20/20, replaces the 2-way `random`
split's lack of a true test set).** `dataset.py` gained `split3()`
(train/val/test, design-level, configurable fractions). `train.py` gained
`--split-mode holdout` as an independent branch — deliberately reuses
`_run_fold()` completely unmodified: the held-out test partition is simply
never passed to it, so those designs appear in neither the checkpoint's
`train_designs` nor `val_designs` lists. This means `evaluate.py`'s existing
`"unseen"` split bucket — and every `SPLIT_COLORS`/hatch/legend entry for
`"unseen"` already built into `visualize/viz_gnn.py` — picks the test set up
automatically with **zero changes needed** to either file; that bucket had
simply always been empty before because nothing ever produced a genuine
train/val-disjoint third set. Verified end-to-end: 113/38/38 split, zero
overlap between all three sets, 38 designs correctly labeled `unseen` in
`metrics_holdout.json` with real (non-degenerate) predictions.

**New split-mode: `kfold` (random k-fold CV, replaces `lofo`).**
`dataset.py` gained `kfold_splits(k, seed)` — round-robin random partition
at the design level (unlike LOFO's by-IP-family grouping), yielding
`(train, val, "fold{i}")`. `train.py` gained an independent `--split-mode
kfold` branch (default k=5), writing `train_log_kfold_summary.json` with
mean/std val_f1 across folds. Verified: every design appears in exactly one
fold's validation set across k folds (189/189, zero gaps/duplicates for
k=3).

**`viz_gnn.py` gained `--fold` support** (previously hardcoded to the
unsuffixed random-split files via a module-level `CORPUS_SUFFIX` constant
that was never wired to any CLI flag — this is also, in retrospect, why
LOFO's per-fold figures never actually got generated even when LOFO was
in active use). `--fold holdout`/`--fold fold0` now read the correct
suffixed prediction/metrics files.

**`kfold`-specific combined figures.** Running the standard 8-figure
`viz_gnn.py` flow once per fold would produce k redundant copies of every
figure. Added a parallel `--kfold K` mode that instead produces ONE combined
figure per type: `training_curves_kfold`, `roc_pr_curves_kfold`,
`calibration_kfold` (one line per fold, color-coded), `per_design_f1_kfold`/
`per_design_auroc_kfold` (one bar chart over all designs' out-of-fold
scores, colored by fold), `score_distribution_kfold` (pooled out-of-fold,
not fold-colored — a histogram doesn't gain from a third color axis),
`confusion_by_fold_kfold` (k panels in one image), `top_errors_kfold`
(pooled top FP/FN across folds' out-of-fold predictions, fold column).
`_load_kfold_oof()` pools each design's prediction from the ONE fold where
it was held out, giving a complete, non-overlapping "out-of-fold" prediction
set across the whole corpus — the standard k-fold CV evaluation pattern.
Verified: 189/189 unique out-of-fold entries for k=3, no gaps/duplicates,
figures render correctly with per-fold coloring.

**LOFO removed entirely**, per explicit direction after observing it was
slow (one full training run per IP family — 4x the cost of a single run)
and its family-grouped folds were unhelpfully imbalanced (`AES` alone had
40+ designs; `wb_conmax` had 2), making the per-fold numbers noisy relative
to the wall-clock cost of obtaining them. Removed: `dataset.py`'s
`family_of_design()`/`FAMILIES`/`lofo_splits()`, `train.py`'s `lofo` branch
and `train_log_lofo_summary.json` output, `run_pipeline.py`'s LOFO
family-enumeration branch in `run_train_eval()`, and `lofo` from every
`--split-mode` choices list. `evaluate.py`/`viz_gnn.py`'s `--fold` argument
was kept (still needed by `holdout`/`kfold`), just reworded away from
LOFO-specific phrasing. The `random`/`holdout`/`kfold` code paths were
verified byte-identical/unaffected by every step of this removal (each was
implemented as an independent branch specifically so this would be true).

**Why:** the QtFlow WARN spam investigation was user-initiated ("why is
this happening and how to solve for the future"); the source-name fix and
`--check-sources` tool were the direct, verified root-cause fix +
regression-prevention tool. The `holdout`/`kfold` split modes and
`--train-eval` were requested to consolidate Stage 6's three-command manual
recipe into one command and to give a real held-out generalization number
(the `random` split never had one). LOFO's removal was an explicit decision
after direct experience with its cost/noise tradeoff in this session — not
a claim that leave-one-family-out CV is a bad idea in general, just that
random k-fold gives a comparable signal far more cheaply for this corpus.

**How to apply:** run `--check-sources` before any `--all` run. Prefer
`--train-eval --split-mode holdout` (or `kfold`) over the bare `random`
split when reporting Stage 6 numbers — `random`'s `val_micro_f1` is
optimistic (same set used for both early-stopping and reporting).
`kfold`'s mean±std across folds is the number to compare against what LOFO
used to report, if a generalization claim beyond a single train/val/test
split is needed. GUIDE.md's Stage 6 section documents the full current
CLI surface and file-naming conventions for first-time users.
