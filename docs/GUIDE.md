# IFT Pipeline — User Guide

This is the document to open when you are staring at output files and asking
"what does this mean?" It answers the questions that come up naturally, in the
order they come up.

---

## Quick Start

**First time in this repo? Run this before anything else:**

```bash
# from the repository root
python3 run_pipeline.py --check-sources
```

This is a fast, read-only sanity check — it does not run synthesis or
scoring. It lists any discovered design with no taint source configured,
which would otherwise silently produce empty QtFlow scores deep into a full
`--all` run. Fix anything it flags (see the "No sources configured"
entry in the Debugging Checklist) before running the full pipeline.

```bash
# Run the full pipeline for all designs (~2 minutes for the 5-design AES set;
# longer for the full 190-design corpus):
python3 run_pipeline.py --all

# Run for one design only:
python3 run_pipeline.py --design AES-T2100

# Regenerate all figures without rerunning analysis:
python3 run_pipeline.py --compare

# Rerun from a specific stage (1–6) without redoing earlier work:
python3 run_pipeline.py --design AES-T2100 --from-stage 4

# Train + evaluate + generate all GNN figures in one command (see Stage 6 below):
python3 run_pipeline.py --train-eval --split-mode holdout
```

**Outputs land in:** `outputs/{DESIGN_NAME}/`
**Figures land in:** `outputs/figures/`
**The file you care most about:** `outputs/{DESIGN}/fusion_report.txt` — read this first.

**Note on `--force`:** if you edit `config/designs.json` (e.g. adding a
`sources` override) and re-run `--all`/`--design` *without* `--force`, the
pipeline now detects that the config changed since a design's last run and
automatically forces a recompute for that design — you'll see `config/
designs.json changed since last run — forcing recompute` printed. You don't
need to remember to pass `--force` yourself after a config edit.

---

## The Big Picture

### What is taint?

"Taint" is a mark that propagates through a circuit from secret inputs to outputs.
Start with the secret key and state inputs marked as tainted (taint = 1).
Every gate/signal they feed into also becomes tainted, and so on through the circuit.
A Trojan is suspicious if secret data can flow through it — meaning it can leak
or act on the key. Taint tracking finds these paths automatically.

The score (0.0–1.0) measures *how strongly* a signal is connected to the secret:
- **0.0** = completely clean, no connection to the key whatsoever
- **0.8+** = the key/state inputs themselves
- **0.1–0.3** = suspicious signals deep in the circuit (Trojan intermediates)
- **0.05–0.1** = weakly connected (many hops away)

### Why two analysis paths?

There is a fundamental problem: **Yosys synthesis removes "dead" logic.**

AES-T2100's power-side-channel Trojan works by XOR-ing the secret key into an
inverter chain that modulates power consumption. There is no digital output —
it doesn't appear on any output pin. Yosys sees this as "dead code" and deletes
it during synthesis. From the gate-level netlist, the Trojan simply does not exist.

This is why two parallel analyses are needed:

| | DFG (gate-level) | AST (source-level) |
|---|---|---|
| Source | Yosys synthesized netlist | Raw Verilog source files |
| Built by | `run_yosys.py` + `dfg_taint.py` | `run_ast.py` |
| Sees | All digital signal paths | All declared signals including dead code |
| Blind to | Dead logic, power-only paths | Cross-module port connections |
| T2100 COUNTER score | **0.000** (Yosys removed it) | **0.150** (found via sensitivity list) |

The **core thesis finding** is that T2100's COUNTER showing 0.000 in DFG and
0.150 in AST is **correct behaviour, not a bug.** See the dedicated section below.

---

## Files Explained (in pipeline order)

Each design produces the following files in `outputs/{DESIGN_NAME}/`:

### Stage 1 outputs

**`netlist.json`** (6–7 MB)
The Yosys-synthesized gate-level netlist. This is the machine-readable circuit
description: every logic gate (cell), every wire (net), and their connections.
You will almost never open this manually — the pipeline reads it for you.
If this file is missing, no DFG analysis can run.

**`ast_nodes.csv`** (~300 KB, ~5000–5300 rows)
Every node in the Verilog source's Abstract Syntax Tree — module definitions,
always blocks, assignments, signal declarations, identifiers, constants.
One row per AST node. This is what the AST taint analysis operates on.
Columns: `node_id, parent_id, ast_type, signal_name, module_name, lineno, depth,
timing_sensitive, taint_binary, taint_score, role, is_on_trojan_path, dist_source`

**`ast_edges.csv`**
Parent→child relationships between AST nodes. Used to reconstruct the tree
structure for GNN training.

**`ast_taint_scores.json`** (~25 KB)
The per-signal taint results from the AST analysis, aggregated to unique signal
names (e.g., "COUNTER", "SECRETKey", "key"). This is the human-readable summary
of what the AST path found. Open this to quickly check a specific signal's AST score.

**`ast_report.txt`** ← **Read this after AST runs**
Plain-text summary: how many nodes, how many tainted, score range, top 20 tainted
signals with their scores and roles. This is your first sanity check.

### Stage 2 outputs (DFG taint)

**`taint_scores.json`** (~1.8 MB)
The per-node taint results from the DFG analysis. Every node in the netlist
(cells + nets) gets a taint_binary and taint_score. Large because the flat
netlist has ~5000 nodes. Open `ast_taint_scores.json` instead for quick lookups
since DFG nodes have long internal names like `$flatten\a1.$xor$...`.

**`dfg_nodes.csv`** (~450 KB)
The DFG graph in node table form for GNN. Every netlist node is one row.
Columns: `node_id, node_name, role, role_enc, kind, cell_type, width,
taint_binary, taint_score, path_score, fanout_score, dist_source, dist_sink,
is_on_trojan_path, is_fsm_state_reg`

**`dfg_edges.csv`** (~350 KB)
The DFG graph in edge list form. Each row is a directed connection: `src_id →
dst_id`, with flags for whether each endpoint is tainted and whether the edge
is on the trojan path.

**`dfg_taint_report.txt`** ← **Read this after DFG runs**
Plain-text summary: total nodes, tainted count, ghost nodes added, sink
coverage, score breakdown by role, and a list of every node on the trojan path.
For T2100 you should see: "Ghost added: 12" and "On Trojan path: 12".

### Stage 3 outputs (golden baseline + Phase 1 + Phase 2 scoring)

**`golden_scores.json`** (~1.5 MB)
Taint scores computed on the same netlist with Trojan cells masked out.
This is the "what would the circuit look like without the Trojan" baseline.
Same format as `taint_scores.json`.

**`golden_nodes.csv`** (~425 KB)
Same as `dfg_nodes.csv` but for the golden (Trojan-free) graph.

**`delta_scores.json`** (~860 KB)
Per-node difference: `full_score − golden_score`. Positive delta means the Trojan
made this signal more suspicious. Zero delta means the Trojan didn't touch it.
Nodes with `is_trojan_only: true` only exist in the Trojan version (they are the
Trojan itself).

**`golden_report.txt`** ← **Read this to see what the Trojan actually changed**
Lists the top nodes by |delta|. For T2100 you should see 45 trojan-only nodes,
all flagged with `[TROJAN-ONLY]`, with scores ranging from +0.081 to +0.303.

**`glra_dfg_scores.json`** — Phase 1: GLRA (Graph Leakage Risk Assessment)
Per-signal risk score comparing Transmission Cost (TC) along paths in the target vs golden graph.
```json
{
  "SECRETKey": {
    "target_tc": 1.2, "golden_tc": null, "leak_ratio": null,
    "risk_score": 0.85,
    "category": "INJECTED"
  }
}
```
Categories: `INJECTED` (trojan-only path), `ELEVATED` (cheaper path than golden), `TARGET_ONLY`,
`REDUCED`, `GOLDEN_ONLY`, `NO_CHANGE`. Risk score = 1.0 means maximum leakage risk; 0.5 = neutral.

**`qtflow_dfg_scores.json`** — Phase 2: QtFlow DFG timing leakage (gate-level)
Per-signal Timing Leakage Score (TLS) from BFS over the Yosys netlist.
Timing taint is seeded where data-taint reaches a control-flow gating port
(`$mux` select, `$eq`/`$ne` any input, `$memrd_v2` ADDR, `$dlatch` EN).
```json
{
  "Trojan.trigger": {
    "target_cycles": 3, "target_cycle_var": 0,
    "golden_cycles": null, "cycle_delta": null,
    "timing_tainted_target": true, "timing_tainted_golden": false,
    "ctrl_channels_reached": 1,
    "tls": 0.618,
    "category": "TIMING_INJECTED"
  }
}
```
TLS formula: `0.40×timing_taint + 0.25×cycle_proximity + 0.20×ctrl_count + 0.15×cycle_delta`
Categories: `TIMING_INJECTED` (new channel), `TIMING_ELEVATED` (earlier cycle), `TIMING_CONTROL`
(existing channel), `TIMING_REDUCED`, `TIMING_GHOST` (power-side-channel artefact), `TIMING_SAFE`.

**`qtflow_ast_scores.json`** — Phase 2b: QtFlow AST timing leakage (source-level)
Same structure as `qtflow_dfg_scores.json` but derived from PyVerilog AST.
Catches power-side-channel timing leaks invisible to Yosys (e.g. T2100's inverter chain:
13 `TIMING_INJECTED` signals via sens-list back-propagation).

### Stage 4 output (fusion)

**`combined_labels.json`** (~90 KB) ← **THE main output**
The fused result from both DFG and AST analysis. One entry per unique signal
name across both analyses. This is the file you hand to anyone downstream.
Each entry has: `dfg_score, ast_score, combined_score, category, timing_sensitive,
is_on_trojan_path, delta_score, is_injected, is_anomaly` plus Phase 1/2 fields:
`glra_dfg_risk, glra_dfg_category, qtflow_dfg_tls, qtflow_dfg_category,
qtflow_ast_tls, qtflow_ast_category, ...`

**`fusion_report.txt`** ← **Read this to understand the thesis result**
Plain-text breakdown: category counts, key trojan signal scores (DFG vs AST),
list of AST_ONLY_HIGH signals (signals Yosys removed), timing-sensitive signals.
This is the file that shows COUNTER = `AST_ONLY_HIGH`.

### Stage 5 outputs (GNN export)

**`hw2vec/node_features.npy`** — Feature matrix, shape (N, 14), float32
**`hw2vec/edge_index.npy`** — Edge list, shape (2, E), int64 (COO format)
**`hw2vec/labels.npy`** — Binary labels, shape (N,), int64
**`hw2vec/metadata.json`** — Design info, feature names, node names list

See the [HW2VEC / GNN Handoff](#hw2vec--gnn-handoff) section for how to use these.

---

### Stage 6 outputs (GNN training)

Stage 6 trains a node-level binary classifier on the Stage 5 exports. It is
**dataset-wide** — one training run consumes every design that has a
`hw2vec/` directory. Code lives in `stage6_train/`:

```
stage6_train/
├── dataset.py     # IFTNodeDataset: loads all hw2vec/*.npy into PyG Data list
├── model.py       # GraphSAGE (primary) + GCN (baseline)
├── train.py       # BCEWithLogitsLoss + pos_weight, early stop on val F1
└── evaluate.py    # per-design + aggregate metrics, confusion matrix, predictions dump
```

#### The easy way: one command

```bash
# Train, evaluate, and generate every figure in one shot:
python3 run_pipeline.py --train-eval --split-mode holdout
```

This is the recommended way to run Stage 6 for the first time. It chains
`stage6_train.train` → `stage6_train.evaluate` → `visualize.viz_gnn`
automatically, so you don't need to remember the manual 3-step recipe below.
Useful flags (all documented in `python3 run_pipeline.py --help`):

```bash
--model {sage,gcn}         # architecture (default: sage)
--split-mode {random,holdout,kfold}   # see below (default: random)
--epochs N --lr F --batch-size N --patience N --seed N
--thresh F                 # decision threshold for evaluation/figures (default: 0.5)
--calibrate                # also report the per-design F1-maximizing threshold
```

#### The manual way (equivalent, run stage-by-stage)

```bash
# from the repository root

# 1. Train (GraphSAGE, 100 epochs, early-stop on val F1, GPU if available):
python3 run_pipeline.py --train --split-mode holdout
# ...or directly:      python3 -m stage6_train.train --model sage --split-mode holdout

# 2. Evaluate (writes metrics*.json + predictions*.npz + confusion-matrix figure):
python3 -m stage6_train.evaluate --model sage --fold holdout

# 3. Generate the 8 figures:
python3 -m visualize.viz_gnn --model sage --fold holdout
```

A 36-design run on a single GPU finishes in ~30 seconds; on CPU it takes a
minute or two. The full 190-design corpus takes longer, scaling with
`--epochs`. Early stopping (patience=10 epochs by default, monitor=val F1)
usually fires well before the epoch budget is used up.

#### Choosing a `--split-mode`

All splits happen **at the design level** (whole synthesized circuits), never
within a design's own graph — node-level splitting would leak structure
across a design's own DFG.

| Mode | What it does | When to use it |
|------|--------------|-----------------|
| `random` (default) | Fixed-seed 80/20 train/val split, **no held-out test set**. | Quick smoke test. The val set is used for both early-stopping *and* the reported metric, so its numbers are optimistic — not a true generalization estimate. |
| `holdout` | Fixed-seed 3-way split, default **60/20/20** (`--val-frac`/`--test-frac` to change). The test 20% is never touched by training or checkpoint selection. | **Recommended default for anything you want to report.** The test set gives a genuine, unbiased generalization number — evaluate.py's `unseen` bucket, previously always empty under `random`, is now populated with real held-out designs. |
| `kfold` | k-fold CV, **randomly** partitioned at the design level (`--k`, default 5). Every design is validated exactly once, out-of-fold, across the k folds. | When you want a mean±std generalization estimate instead of a single train/val/test split, or want every design to get an out-of-fold prediction (no design is ever "just training data"). |

`holdout` and `kfold` write fold-suffixed files (`sage_holdout_best.pt`,
`sage_fold0_best.pt`, ...) so they never clobber each other or the plain
`random` run's unsuffixed files. Note: an earlier `lofo` (leave-one-family-out)
mode existed and was removed — it required one full training run per IP
family (4x the cost of a single run) and its family-grouped folds were
wildly imbalanced (one family had 40+ designs, another had 2), making the
per-fold numbers noisy and slow to obtain. `kfold`'s randomly-balanced folds
give a comparable generalization signal much more cheaply.

#### What the dataset looks like

`IFTNodeDataset` walks `discover_designs()` and turns each `outputs/<D>/hw2vec/`
into a `torch_geometric.data.Data(x, edge_index, y, design_name)`. Designs
without an `hw2vec/` subdir are skipped automatically (printed as `skipped`).
The 14-dim feature ordering is the same as `stage5_export/hw2vec_export.py`
lines 12–26 (taint_score, ast_score, combined_score, is_on_trojan_path,
timing_sensitive, role_enc_norm, cell_type_enc, width_norm, dist_source_norm,
delta_score, is_injected, glra_dfg_risk, qtflow_dfg_tls, qtflow_ast_tls).

Class imbalance is handled by `BCEWithLogitsLoss(pos_weight=neg/pos)` measured
on the **training** subset only (so val/test never leak into it).

#### Files written

Filenames get a `_<fold>` suffix for `holdout` (`_holdout`) and `kfold`
(`_fold0`, `_fold1`, ...); `random` writes the plain unsuffixed names shown
here:

```
outputs/gnn/
├── checkpoints/
│   └── sage_best.pt              # best-by-val-F1 weights + train/val (+ test, for holdout) design names
├── train_log.json                # per-epoch loss/F1/AUROC for diagnosis
├── train_log_kfold_summary.json  # kfold only: mean/std val_f1 across folds
├── metrics.json                  # per-design + aggregate metrics from evaluate.py
├── predictions_sage.npz          # per-node probs + true labels (feeds viz_gnn.py)
├── predictions_sage_splits.json  # design -> "train"/"val"/"unseen"
└── figures/
    ├── confusion_matrix_sage.png              # from evaluate.py
    ├── training_curves_sage.png                # from viz_gnn.py (8 figures total)
    ├── roc_pr_curves_sage.png
    ├── score_distribution_sage.png
    ├── calibration_sage.png
    ├── per_design_f1_sage.png
    ├── per_design_auroc_sage.png
    ├── confusion_by_split_sage.png
    └── top_errors_sage.png
```

`sage_best.pt` embeds the train/val (and test, for `holdout`) design name
lists so `evaluate.py` can honor the same split deterministically without
re-running the seed dance. A design that's in neither the checkpoint's
`train_designs` nor `val_designs` list is automatically classified `unseen`
by `evaluate.py` — this is how `holdout`'s test set ends up correctly
labeled without any extra plumbing.

#### `kfold`'s combined figures are different

Because `kfold` trains k separate models, running `viz_gnn.py` once per fold
would give you k copies of every figure. Instead, `run_pipeline.py
--train-eval --split-mode kfold` generates **one combined figure per type**,
color-coded by fold, written under the same `outputs/gnn/figures/` directory
with a `_kfold_` infix (e.g. `training_curves_kfold_sage.png`,
`roc_pr_curves_kfold_sage.png`, `per_design_f1_kfold_sage.png`,
`confusion_by_fold_kfold_sage.png`). Where possible (line/scatter plots,
per-design bars) each fold gets its own color; for the score-distribution
figure, all folds' out-of-fold predictions are pooled into one combined
view instead, since color-by-fold doesn't add information there. To
regenerate just these without retraining: `python3 -m visualize.viz_gnn
--model sage --kfold 5` (after `stage6_train.evaluate --fold fold{i}` has
been run for every fold).

#### Reading `metrics.json`

```json
{
  "model": "sage",
  "fold": "holdout",
  "best_epoch": 10,
  "aggregate": {
    "val_macro_f1": 0.44,        // mean F1 across val designs
    "val_micro_f1": 0.93,        // F1 over all val nodes pooled together
    "val_micro_auroc": 0.94,     // ranking quality, threshold-invariant
    "n_train": 113, "n_val": 38
  },
  "per_design": {
    "AES-T1600": { "split": "val", "f1": 0.80, "precision": 1.00,
                   "recall": 0.67, "auroc": 0.99, "n_pos": 106, "support": 5087 }
  },
  "top_false_positives": [ ... ],   // 15 highest-prob clean nodes (classifier overconfidence)
  "top_false_negatives": [ ... ]    // 15 lowest-prob trojan nodes (label/feature gaps)
}
```

`per_design[...]["split"]` is one of `"train"`, `"val"`, or `"unseen"` —
for `holdout` runs, `"unseen"` is the genuinely held-out test set and its
aggregate numbers (visible in the `confusion_by_split`/`roc_pr_curves`
figures' third panel/line) are the ones worth reporting, not `val`'s.

The macro-F1 / micro-F1 gap is meaningful: when **macro ≪ micro**, a few
designs with tiny positive sets (e.g. 3 trojan nodes / 1616 total) are
dragging the average down at the 0.5 threshold even though their AUROC is
high. `--calibrate` (a per-design threshold sweep) fixes this — it's not a
training problem. The top-FP / top-FN tables are the thesis-discussion
goldmine — they pinpoint exactly which nodes the IFT label-fusion stage is
mislabeling.

#### What "good" looks like

- **Stable training:** no NaN losses, val loss trending down for the first
  ~10–20 epochs.
- **Val/test micro-AUROC > 0.85** (we hit 0.94 on the first run).
- **Val/test micro-F1 > 0.85** (we hit 0.93 on `random`; expect it to be a
  little lower on `holdout`'s genuinely unseen test set — that's the honest
  number).
- A design with low F1 but high AUROC = threshold issue, not a model problem
  (use `--calibrate`).
- A design with low AUROC = real failure — investigate the labels and
  features for that design before blaming the model. On our run, `AES-T2300`
  AUROC=0.54 cleanly flagged the known Stage-4 limitation that the AST stage
  doesn't trace cross-module trojan instantiation.

#### Out of scope (deferred)

- Graph-level TjFree-vs-TjIn classification — needs Stages 1–5 re-run on
  `TjFree/` sources with `--variant tjfree` (implemented; see
  `PIPELINE_LOG.md` for status/coverage).
- A direct comparison with the UCSD `hw2vec` library on raw Verilog.

---

## What the Numbers Mean

### `taint_binary` (0 or 1)
Is this signal reachable from the secret key through data flow?
- 1 = yes, the key can influence this signal
- 0 = no connection to the key whatsoever

### `taint_score` (0.0 to 1.0)
How strongly suspicious is this signal? Computed by the QFlow formula:

```
score = 0.40 × path_score
      + 0.20 × fanout_score
      + 0.15 × width_score
      + 0.25 × role_bonus
```

Where:
- `path_score = 1 / (1 + dist_from_source)` — closer to key = higher
- `fanout_score = min(fanout / 20, 1.0)` — more connections = higher
- `width_score = min(width / 128, 1.0)` — wider bus = higher
- `role_bonus`: source=1.0, sink=0.9, trojan=0.85, key_sched=0.7, internal=0.2

**Scale reference:**
- 0.82 = `key` or `state` (the source inputs themselves)
- 0.38–0.52 = `out` (AES output, one path from source)
- 0.20–0.30 = SECRETKey (directly assigned from key)
- 0.10–0.15 = COUNTER, LEAKBit (2 hops from key via sensitivity list)
- 0.05–0.09 = inverter chain outputs (ghost nodes)
- 0.00 = not tainted

### `dist_source` (integer)
How many assignment/gate hops from the key/state inputs.
- 0 = the source inputs themselves (`key`, `state`)
- 1 = directly assigned from key (e.g. `SECRETKey <= key`)
- 2 = assigned from something dist=1 (e.g. COUNTER in sensitivity list of SECRETKey's always block)
- -1 = not tainted at all

### `is_on_trojan_path` (0 or 1)
Is this signal **both** reachable forward from the key AND reachable backward
from a trojan output? A signal can be tainted (reached from key) without being
on the trojan path (if it only flows to legitimate AES outputs).

The difference from `taint_binary`:
- `key` → tainted, but NOT on trojan path (it flows to both AES out and Trojan, but the path going to AES `out` is not the trojan path)
- `SECRETKey` → tainted AND on trojan path (it feeds the inverter chain)
- `a1.v0` (AES round key) → tainted but NOT on trojan path (it only feeds `out`)

### `role`
How the signal is classified:
- `source` — secret key or state inputs
- `sink` — AES ciphertext output (`out`)
- `trojan_intermediate` — signal name matches known Trojan patterns (SECRETKey, COUNTER, LEAKBit, INV*, trigger)
- `key_intermediate` — AES key schedule intermediates (k0a, k1b, v0, v1, ...)
- `internal` — everything else (round state, table lookups, etc.)

### `category` (in `combined_labels.json`)

| Category | Meaning | What to do |
|----------|---------|------------|
| `AGREE_HIGH` | Both DFG and AST score ≥ 0.25, difference < 0.15 | Strong positive label — definitely suspicious |
| `AGREE_LOW` | Both analyses say it's clean (< 0.08) | Safe to label as clean |
| `DFG_ONLY_HIGH` | DFG finds it suspicious, AST doesn't | Synthesis artefact or AES intermediate |
| `AST_ONLY_HIGH` | AST finds it suspicious, DFG score < half of AST | **Dead code / power-only Trojan** — Yosys removed it |
| `DIVERGE` | Both see some taint but very different scores | Investigate — possibly scoring difference |
| `DFG_ONLY` | Signal appears in DFG but not in AST | Internal Yosys cell name |
| `AST_ONLY` | Signal appears in AST but not in DFG | Declared but not synthesized |

### `delta_score`
`full_taint_score − golden_taint_score`. The golden baseline is the same circuit
with Trojan cells masked out.
- Positive delta → the Trojan made this signal more suspicious
- Zero delta → the Trojan didn't affect this signal's information flow
- `is_trojan_only: true` → this node only exists in the Trojan version (it IS the Trojan)

### `is_injected` (0 or 1)
The node was clean (taint=0) in the golden baseline but tainted (taint=1) in the
full Trojan design. This is the strongest signal of Trojan involvement — the
Trojan introduced new information flow that didn't exist before.

---

## The Core Thesis Result Explained

**COUNTER in AES-T2100 shows `DFG = 0.000` and `AST = 0.150`. This is correct. Not a bug.**

Here is what is happening in the Verilog (TSC.v):

```verilog
// COUNTER is a 128-bit counter that increments on every clock edge.
// It has NO connection to key or state in the data path.
always @(posedge clk)
    COUNTER <= COUNTER + 1;

// But COUNTER controls WHEN SECRETKey is captured:
always @(posedge COUNTER[127])   // ← sensitivity list
    SECRETKey <= key;             // ← SECRETKey is assigned from key

// SECRETKey then feeds an inverter chain (power modulation):
// INV1_out → INV2_out → ... → INV11_out → LEAKBit → Antena
```

**Why DFG misses it (score = 0.000):**
The inverter chain (INV1–INV11, LEAKBit) has no digital output port. Yosys treats
it as "dead code" and removes it during synthesis. In the flat netlist, there is
literally no connection from COUNTER to any output. The BFS taint propagation
cannot find a path that doesn't exist in the synthesized circuit.

**Why AST catches it (score = 0.150):**
The AST walker sees the raw Verilog, including the sensitivity list
`@(posedge COUNTER[127])`. The two-pass taint propagation works as follows:
1. Pass 1 (data assignments): `SECRETKey <= key` → SECRETKey is tainted at dist=1
2. Pass 2 (sensitivity lists): the always block that assigns SECRETKey has `COUNTER`
   in its sensitivity list → COUNTER is tainted at dist = 1 + 1 = **2**

COUNTER controls *when* the secret is captured, creating a timing side-channel.
The power drawn by the inverter chain depends on the XOR of the key bits. This is
detectable at the power supply level — but invisible to any gate-level analysis.

**Key signal table for AES-T2100:**

| Signal | DFG score | AST score | Category | Role |
|--------|-----------|-----------|----------|------|
| key | 0.830 | 0.670 | AGREE_HIGH | source |
| state | 0.810 | 0.668 | AGREE_HIGH | source |
| SECRETKey | 0.303 | 0.217 | DIVERGE | trojan_intermediate |
| **COUNTER** | **0.000** | **0.150** | **AST_ONLY_HIGH** | trojan_intermediate |
| LEAKBit | 0.081 | 0.149 | AGREE_LOW | trojan_intermediate |
| Tj_Trig | 0.000 | 0.152 | AST_ONLY_HIGH | trojan_intermediate |
| out | 0.381 | 0.520 | AGREE_HIGH | sink |

---

## Design-by-Design Results

What to expect from each design's analysis:

| Design | Trojan Type | DFG Trojan Path | AST Trojan Path | Trigger Category | Note |
|--------|-------------|-----------------|-----------------|------------------|------|
| **T2100** | Power side-channel | 12 nodes (ghost only) | 61 nodes | `AST_ONLY_HIGH` | Core thesis design |
| **T2300** | Combinational trigger | 1158 nodes | 0 nodes* | DFG detects | AES intermediates gate the trigger |
| **T2400** | Combinational trigger | 1618 nodes | 0 nodes* | DFG detects | Same mechanism as T2300 |
| **T2500** | Clock-only counter | **0 nodes** | **0 nodes** | `AGREE_LOW` | Both analyses miss it — see below |
| **T2600** | Data-conditioned counter | 705 nodes | 0 nodes* | DFG detects | Counter gated by AES intermediate |

*AST limitation: module instantiation port connections are not traced cross-module.
The Verilog has `TSC Trojan(s2[89], s5[121], Tj_Trig)` — AST sees `r1, r2` as
input ports inside TSC but doesn't connect them to `s2[89]` in the parent. DFG
handles this correctly via the flat netlist.

### T2500 shows 0 trojan path nodes — is my pipeline broken?

**No. This is the correct result.** T2500's TSC module is:

```verilog
always @(posedge clk)
    counter = counter + 1;    // counter uses ONLY clk — no key, no state
assign trigger = counter[3];  // trigger fires after 8 clock cycles
```

The counter has no data input from the AES computation at all. It increments
purely on clock edges. There is no information flow from `key` or `state` to
`trigger` — neither in the data path (DFG) nor in the sensitivity list (AST).
Both analyses correctly give 0.000 because the Trojan is genuinely undetectable
by information flow tracking. It would only be detectable by timing analysis
(it fires after exactly 8 clock cycles — a deterministic, data-independent trigger).

This is a genuine research finding, not a pipeline failure.

---

## How to Know You're Progressing

Run the pipeline with `--force` to recompute and check these numbers:

### After Stage 1 — Yosys Synthesis
Console should print something like:
```
[AES-T2100] Synthesis complete: 1 module(s), 2039 cells, 2930 named nets
```
Check: `outputs/AES-T2100/netlist.json` exists and is ~6 MB.

| Design | Expected cells | Expected nets |
|--------|---------------|---------------|
| T2100 | 2039 | 2930 |
| T2300 | 2028 | 2898 |
| T2400 | 2028 | 2898 |
| T2500 | 2030 | 2901 |
| T2600 | 2031 | 2903 |

**If wrong:** T2100 with significantly fewer nets → `keep_signals` not working.
Check that `designs.json` has the `keep_signals` entry for T2100.

### After Stage 2 — AST Extraction
Open `outputs/{DESIGN}/ast_report.txt`. For T2100:
```
Total AST nodes  : 5316
Tainted signals  : 49
Tainted nodes    : 874  (16.4%)
On Trojan path   : 61
```
Top signal in TOP TAINTED SIGNALS should be `key` with score ~0.670.
COUNTER should appear in the list with score ~0.150 and dist=2.

### After Stage 3 — DFG Taint
Open `outputs/{DESIGN}/dfg_taint_report.txt`. For T2100:
```
Tainted  : 2202/4969
Ghost nodes added: 12
On Trojan path   : 12
```
Sinks reached should include `out`. COUNTER should have taint_binary=0 in
`taint_scores.json` (this is correct — DFG cannot see it).

### After Stage 4 — Golden Baseline
Open `outputs/{DESIGN}/golden_report.txt`. For T2100:
```
Total nodes  : 4924 (golden, excl. 45 trojan)
```
TOP DELTA NODES should list `Trojan.SECRETKey` with Δ=+0.303 and [TROJAN-ONLY].

### After Stage 5 — Label Fusion
Open `outputs/{DESIGN}/fusion_report.txt`. For T2100, the KEY TROJAN SIGNALS
section must show:
```
COUNTER    DFG=0.000  AST=0.150  cat=AST_ONLY_HIGH
Tj_Trig    DFG=0.000  AST=0.152  cat=AST_ONLY_HIGH
```
If COUNTER shows `cat=AGREE_LOW`, the threshold in `fuse_labels.py` is wrong.

### After Stage 6 — GNN Export
Open `outputs/{DESIGN}/hw2vec/metadata.json`. For T2100:
```json
{
  "n_nodes": 4969,
  "n_edges": 3383,
  "n_trojan": 45,
  "n_clean": 4924,
  "feature_dim": 14
}
```
Run the sanity check (see HW2VEC section below).

---

## Visualizations

All figures are PNG files. Open with any image viewer.

### Where they are

```
outputs/figures/
│
│  ── Fusion / DFG vs AST comparison (viz_compare.py) ─────────────────────
├── fig_full_comparison.png       ← THE thesis figure (all 5 panels, 20×22 in)
├── fig_detection_scatter.png     ← Detection rate bars + DFG vs AST scatter
├── fig_ast_count_heatmap.png     ← AST-only counts + delta heatmap
├── fig_summary_table.png         ← Design-by-design detectability table
│
│  ── Phase 1 GLRA risk bars (viz_glra_bars.py) ────────────────────────────
├── fig_glra_AES-T2100.png        ← Per-design GLRA risk bars (one file each)
├── fig_glra_AES-T2300.png
├── ...
│
│  ── Phase 2 QtFlow timing (viz_qtflow.py) ────────────────────────────────
├── fig_qtflow_AES-T2100.png      ← Per-design DFG vs AST TLS bars (one each)
├── fig_qtflow_AES-T2600.png
├── ...
├── fig_qtflow_compare.png        ← Cross-design 4-panel overview
├── fig_qtflow_category_stacks.png
├── fig_qtflow_dfg_ast_scatter.png
├── fig_qtflow_injected_bar.png
└── fig_qtflow_heatmap.png
```

### What each cross-design figure shows

**`fig_full_comparison.png`** — The complete 5-panel thesis figure (DFG vs AST fusion):
- Top-left: grouped bar chart — % of signals in each category (AGREE_HIGH, AST_ONLY_HIGH, etc.) per design
- Top-right: scatter plot — DFG score vs AST score for every signal, coloured by design. Points above the diagonal = AST sees more than DFG. T2100's COUNTER/Tj_Trig should appear above the diagonal in red.
- Bottom-left: bar chart — number of AST_ONLY_HIGH signals per design. T2100 should stand out.
- Bottom-right: heatmap — mean |delta_score| per design × signal role. Where the Trojan perturbs information flow most.
- Bottom-spanning: summary table — one row per design with DFG detects ✓/✗, AST detects ✓/✗, top signal.

**`fig_glra_{design}.png`** — Phase 1 GLRA risk bars (one per design):
Horizontal bars showing each signal's `risk_score` deviation from the 0.5 neutral midpoint.
Red bars = signal path became cheaper than golden (more leakage risk). Green = harder.

**`fig_qtflow_{design}.png`** — Phase 2 QtFlow TLS bars (one per design):
Side-by-side DFG (left) and AST (right) Timing Leakage Score bars per signal.
Key result: T2100 shows DFG=0 INJECTED (Yosys removed the chain) but AST=13 INJECTED.
T2600 shows DFG=5 INJECTED (dedicated Trojan counter module).

**`fig_qtflow_compare.png`** — Phase 2 cross-design 4-panel overview:
- Category-share stacked bars (INJECTED/ELEVATED/CONTROL/GHOST/SAFE)
- Mean DFG-TLS vs AST-TLS scatter
- TIMING_INJECTED signal count per design
- TLS heatmap (mean TLS and INJECTED% per design × DFG/AST)

### How to regenerate figures

```bash
# All three scripts (recommended):
python3 run_pipeline.py --compare

# Individual scripts:
python3 visualize/viz_compare.py              # fusion comparison
python3 visualize/viz_glra_bars.py --all      # GLRA risk bars
python3 visualize/viz_qtflow.py --all         # per-design QtFlow bars
python3 visualize/viz_qtflow.py --compare     # cross-design QtFlow overview
```

`viz_compare.py` reads `combined_labels.json`; `viz_glra_bars.py` reads `glra_dfg_scores.json`;
`viz_qtflow.py` reads `qtflow_dfg_scores.json` and `qtflow_ast_scores.json`.

---

## HW2VEC / GNN Handoff

### The 3 files to load

For each design:
```
outputs/{DESIGN}/hw2vec/node_features.npy   # shape (N, 14), float32
outputs/{DESIGN}/hw2vec/edge_index.npy      # shape (2, E),  int64
outputs/{DESIGN}/hw2vec/labels.npy          # shape (N,),    int64
```

Where N = number of nodes (4969 for T2100), E = number of edges (3383 for T2100).

### Loading with numpy + PyTorch Geometric

```python
import numpy as np
import torch
from torch_geometric.data import Data

design = "AES-T2100"
base   = f"outputs/{design}/hw2vec"

# Load
features   = np.load(f"{base}/node_features.npy")   # (N, 14) float32
edge_index = np.load(f"{base}/edge_index.npy")       # (2, E)  int64
labels     = np.load(f"{base}/labels.npy")           # (N,)    int64

# Sanity checks
assert features.shape[1] == 14
assert features.min() >= 0.0 and features.max() <= 1.0
assert labels.sum() == 45   # T2100 has 45 trojan nodes

# Convert to PyTorch Geometric Data object
data = Data(
    x         = torch.tensor(features, dtype=torch.float),
    edge_index = torch.tensor(edge_index, dtype=torch.long),
    y         = torch.tensor(labels, dtype=torch.long),
)
print(data)
# Data(x=[4969, 14], edge_index=[2, 3383], y=[4969])
```

### The 14 feature columns (in order)

| Index | Feature name | Range | What it means |
|-------|-------------|-------|---------------|
| 0 | `taint_score` | 0–1 | DFG quantitative taint score |
| 1 | `ast_score` | 0–1 | AST quantitative taint score |
| 2 | `combined_score` | 0–1 | Fused DFG+AST score |
| 3 | `is_on_trojan_path` | 0 or 1 | On the path from key to trojan output (DFG) |
| 4 | `timing_sensitive` | 0 or 1 | In a clocked always block or counter-gated (AST) |
| 5 | `role_enc_norm` | 0–1 | Role: source=1.0, sink=0.8, trojan=0.6, key=0.4, internal=0.1 |
| 6 | `cell_type_enc` | 0–1 | Gate type: DFF=0.85, AND=0.4, XOR=0.2, net=0.05 |
| 7 | `width_norm` | 0–1 | Signal bus width / 128 |
| 8 | `dist_source_norm` | 0–1 | 1/(1+dist_from_source): 1.0=source, 0.33=dist2, 0=not tainted |
| 9 | `delta_score` | 0–1 | \|full_score − golden_score\| (how much Trojan perturbs this node) |
| 10 | `is_injected` | 0 or 1 | New taint introduced by the Trojan (strongest Trojan signal) |
| 11 | `glra_dfg_risk` | 0–1 | Phase 1 GLRA leakage risk (0.5=neutral/no data, >0.5=riskier) |
| 12 | `qtflow_dfg_tls` | 0–1 | Phase 2 gate-level Timing Leakage Score (0.5=neutral/no data) |
| 13 | `qtflow_ast_tls` | 0–1 | Phase 2b source-level Timing Leakage Score (0.5=neutral/no data) |

### What the labels mean

```
labels[i] = 0  →  clean node (not part of the Trojan)
labels[i] = 1  →  trojan node (part of or directly driven by Trojan logic)
```

A node is labelled trojan=1 if:
- Its role is `trojan_intermediate`, OR
- Its name starts with `Trojan.` or `$flatten\Trojan.`, OR
- Its `delta_score > 0.05` AND `is_injected = 1`

**Label counts:**

| Design | Total nodes | Trojan nodes | % |
|--------|-------------|-------------|---|
| T2100 | 4969 | 45 | 0.9% |
| T2300 | 4926 | 5 | 0.1% |
| T2400 | 4926 | 5 | 0.1% |
| T2500 | 4931 | 10 | 0.2% |
| T2600 | 4934 | 13 | 0.3% |

Note: Trojan nodes are a small minority in all designs. GNN training will need
class weighting (e.g. `weight=[1.0, 10.0]` for clean vs trojan).

### Loading all designs together

```python
import numpy as np
import torch
from torch_geometric.data import Data, DataLoader

designs = ["AES-T2100", "AES-T2300", "AES-T2400", "AES-T2500", "AES-T2600"]
base    = "outputs"

dataset = []
for design in designs:
    path = f"{base}/{design}/hw2vec"
    data = Data(
        x          = torch.tensor(np.load(f"{path}/node_features.npy"), dtype=torch.float),
        edge_index = torch.tensor(np.load(f"{path}/edge_index.npy"),    dtype=torch.long),
        y          = torch.tensor(np.load(f"{path}/labels.npy"),        dtype=torch.long),
    )
    data.design = design
    dataset.append(data)

loader = DataLoader(dataset, batch_size=1, shuffle=True)
```

---

## Debugging Checklist

### Pipeline won't start
- **Check:** Is Yosys installed? Run `yosys -V` (see `INSTALL.md` if not).
- **Check:** Is PyVerilog available? Run `python3 -c "from pyverilog.vparser.parser import parse; print('ok')"` — if this fails, run `pip install -r requirements.txt`.
- **Check:** Are you running from the repository root (the directory containing `run_pipeline.py`)?

### Stage 1 (Yosys) produces very few Trojan nets for T2100
**Symptom:** "Synthesis complete: 2039 cells" but netlist shows only 5 Trojan nets.
**Cause:** `keep_signals` not applied or applied after `flatten`.
**Fix:** Check `designs.json` has `"keep_signals": ["SECRETKey", "LEAKBit", "INV", "COUNTER", "Tj_Trig"]` for T2100. Check `run_yosys.py` emits `setattr -set keep` **before** the `flatten` step.

### Stage 2 (AST) parse error
**Symptom:** `SyntaxError` or `ParseError` during PyVerilog parsing.
**Cause:** Usually the `, ,` empty port connection in `aes_128.v`.
**Fix:** The preprocessor in `run_ast.py` should handle this automatically with `re.sub(r',(\s*),', r', _nc_ ,', content)`. If it still fails, check which file is failing and inspect that line manually.

### COUNTER shows 0.000 in both DFG AND AST
**Symptom:** Both `taint_scores.json` and `ast_taint_scores.json` show COUNTER taint=0.
**Expected:** DFG=0.000 (correct), AST=0.150 (if AST also shows 0, something is wrong).
**Cause:** The two-pass sensitivity list propagation in `run_ast.py` is not running.
**Check:** Look at `ast_report.txt` — "Tainted signals" should be 49 for T2100, not less.

### All signals show taint_binary = 0
**Symptom:** `dfg_taint_report.txt` shows "Tainted: 0/4969".
**Cause:** The sources (`key`, `state`) were not found in the netlist.
**Fix:** Check `pipeline_config.py` auto-detection. Run `python3 config/pipeline_config.py` to see what sources are detected. For T2100 it should show `sources: ['key', 'state']`.

### "No sources configured" warning / QtFlow figures skip your design ("no QtFlow scores")

**First, run `python3 run_pipeline.py --check-sources`** — it lists every
discovered design with no taint source configured, in seconds, without
running synthesis. Do this before a full `--all` run, not after.

**Symptom:** `[WARN] No sources configured for <design> — taint scores will be all-zero.` during Stage 3, and/or `[WARN] <design>: no QtFlow scores — skipping` when generating comparison figures.

**Cause 1 — genuinely no source detected.** `get_design_config()`'s
auto-detection only treats an input port as a taint source if it's **≥64
bits wide** and its name matches `key|state|plaintext|secret` (see
`pipeline_config.py`, `source_keywords`), with an inline-trojan-comment
fallback for single-file designs. Non-crypto peripherals — UART, SPI, I2C,
PIC16F84, and similar — often have no port matching either heuristic.
**Fix:** Add an explicit `sources` override for that design in
`config/designs.json`, naming whichever signal actually carries the
sensitive/attacker-relevant data (there's no universal answer for non-crypto
peripherals — pick the signal the trojan is meant to leak, e.g.
`mosi_data`/`spi_reg` for an SPI core, `rx_data` for a UART):
```json
"core_basic_spi_master_HT1": {
    "sources": ["mosi_data", "spi_reg"]
}
```

**Cause 2 — a source is detected but doesn't match the synthesized netlist.**
Some design directories ship a stale sibling source file (underscored
signal names) alongside the file Yosys actually synthesizes (often
flattened/renamed, e.g. `trojan_counter_trigger` vs `trojancountertrigger`).
`pipeline_config.py` now auto-resolves this — after detecting a candidate
source name, it checks the name against the real synthesized top module's
signals and, if there's no exact match, tries an underscore-stripped fuzzy
match before giving up. This fixed the majority of previously-broken
designs automatically; if `--check-sources` still flags a design after this,
the true signal name genuinely doesn't exist anywhere in that design's
source (e.g. it's a Verilog `parameter`, or the design has no dedicated
trojan-trigger signal at all) — a manual `designs.json` override, checked
directly against `outputs/<design>/netlist.json`'s `netnames`, is the only
fix.

Once you've added/fixed an override, just rerun (`--all` or `--design
<name>`) **without** `--force` — the pipeline now auto-detects that
`config/designs.json` changed since the design's last run and forces a
recompute for that design only (see the Quick Start note above). You no
longer need to manually pass `--from-stage 3 --force`.

### T2300/T2400/T2600 show 0 trojan path nodes in AST
**This is expected.** Not a bug. The AST does not trace port connections across module instantiation boundaries. The DFG handles this correctly. See the cross-design results table above.

### T2500 shows 0 everywhere
**This is expected.** Not a bug. T2500's Trojan uses a clock-only counter with no data inputs. Neither DFG nor AST can detect it via information flow analysis.

### Ghost nodes = 0 for T2100 in DFG
**Symptom:** `dfg_taint_report.txt` shows "Ghost nodes added: 0".
**Cause:** The ghost_tainted list in `designs.json` uses names that don't match the current netlist.
**Fix:** Open `outputs/AES-T2100/netlist.json` and search for "LEAKBit" to see the actual net names, then update `designs.json` accordingly.

### `combined_labels.json` has COUNTER in AGREE_LOW instead of AST_ONLY_HIGH
**Symptom:** `fusion_report.txt` shows `COUNTER cat=AGREE_LOW`.
**Cause:** AST score is below `AST_DETECT_THRESH = 0.08` or the DFG score is not low enough.
**Fix:** Check `ast_taint_scores.json` for COUNTER's score. If it's genuinely 0, AST propagation failed. If it's 0.15 but still showing AGREE_LOW, check `fuse_labels.py` threshold logic.

### Figures don't generate / matplotlib error
**Fix:** Run `pip install matplotlib numpy`. If the figure window doesn't open, check that `matplotlib.use("Agg")` is set in `viz_compare.py` (it should be — figures save to file, no display needed).
