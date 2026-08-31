"""
run_pipeline.py — IFT Pipeline Orchestrator

Runs the full 5-stage IFT pipeline for one or all designs.
Each stage depends on the previous one; stages can be resumed
from any point if earlier outputs already exist.

Stages:
  1  stage1_extract/run_yosys.py     — Yosys synthesis → netlist.json
  2  stage1_extract/run_ast.py       — PyVerilog AST → ast_nodes.csv, ast_taint_scores.json
  3  stage2_ift/dfg_taint.py         — DFG BFS taint → taint_scores.json
  4  stage3_scoring/golden_delta.py  — Golden baseline → golden_scores.json, delta_scores.json
     stage3_scoring/glra_dfg.py      — Phase 1 leakage risk → glra_dfg_scores.json
     stage3_scoring/qtflow_dfg.py    — Phase 2 timing risk (DFG)  → qtflow_dfg_scores.json
     stage3_scoring/qtflow_ast.py    — Phase 2b timing risk (AST) → qtflow_ast_scores.json
  5  stage4_fusion/fuse_labels.py    — Fuse DFG+AST+GLRA+QtFlow → combined_labels.json
  6  stage5_export/hw2vec_export.py  — 14-dim GNN arrays → hw2vec/

Usage:
    # Full pipeline for one design:
    python3 run_pipeline.py --design AES-T2100

    # All designs:
    python3 run_pipeline.py --all

    # Start from a specific stage (earlier outputs must exist):
    python3 run_pipeline.py --design AES-T2300 --from-stage 4

    # Force recompute all stages:
    python3 run_pipeline.py --design AES-T2100 --force

    # With optional DFG features:
    python3 run_pipeline.py --design AES-T2500 --fsm --tc-model

    # Cross-design comparison figures (run after all designs processed):
    python3 run_pipeline.py --compare
"""

import sys
import argparse
from pathlib import Path

# Allow imports from pipeline root
sys.path.insert(0, str(Path(__file__).parent))
from config.pipeline_config import discover_designs, get_design_config, OVERRIDES_FILE, OUTPUTS_DIR, UnsupportedDesignError

# Import stage functions
from stage1_extract.run_yosys import run_synthesis
from stage1_extract.run_ast   import run_ast
from stage2_ift.dfg_taint     import run_dfg_taint
from stage3_scoring.golden_delta import run_golden_delta
from stage3_scoring.glra_dfg     import compute_glra_dfg
from stage3_scoring.qtflow_dfg   import compute_qtflow_dfg
from stage3_scoring.qtflow_ast   import compute_qtflow_ast
from stage4_fusion.fuse_labels   import fuse
from stage5_export.hw2vec_export import export


STAGE_NAMES = {
    1:  "Yosys synthesis",
    2:  "AST extraction",
    3:  "DFG taint",
    4:  "Golden + GLRA + QtFlow scoring",
    5:  "Label fusion",
    6:  "GNN export",
}


def run_design(design: str, from_stage: int = 1, force: bool = False,
               fsm: bool = False, tc_model: bool = False, variant: str = "tjin"):
    """
    Run the full pipeline for one design starting from `from_stage`.
    Returns True on success, False on failure, None if skipped (unsupported design).

    variant: "tjin" (default) or "tjfree" — tjfree runs Stages 1-6 against the
    clean baseline source tree instead, writing to a separate output namespace
    (outputs/<design>__tjfree/) for graph-level clean-vs-trojan classification.
    """
    print(f"\n{'='*60}")
    print(f"  DESIGN: {design}  [{variant}]")
    print(f"{'='*60}")

    def _stage4_scoring():
        run_golden_delta(design, force=force, variant=variant)
        compute_glra_dfg(design, force=force, variant=variant)
        compute_qtflow_dfg(design, force=force, variant=variant)
        compute_qtflow_ast(design, force=force, variant=variant)

    stages = [
        (1, lambda: run_synthesis(design, force=force, variant=variant)),
        (2, lambda: run_ast(design, force=force, variant=variant)),
        (3, lambda: run_dfg_taint(design, use_tc_model=tc_model,
                                  detect_fsm=fsm, force=force, variant=variant)),
        (4, _stage4_scoring),
        (5, lambda: fuse(design, force=force, variant=variant)),
        (6, lambda: export(design, force=force, variant=variant)),
    ]

    for stage_num, stage_fn in stages:
        if stage_num < from_stage:
            continue
        print(f"\n[Stage {stage_num}] {STAGE_NAMES[stage_num]} ...")
        try:
            stage_fn()
        except UnsupportedDesignError as e:
            print(f"  SKIPPED: {e}")
            return None
        except Exception as e:
            print(f"  ERROR in stage {stage_num}: {e}")
            return False

    return True


def run_compare() -> None:
    """Generate cross-design comparison figures (all three viz scripts)."""
    import subprocess
    pipeline_dir = str(Path(__file__).parent)
    # GLRA per-design bars (viz_glra_bars.py) deliberately dropped — not a
    # useful figure (most designs have no non-neutral GLRA signal; the ones
    # that do don't tell a clearer story than the scatter/heatmap already do).
    scripts = [
        ("visualize/viz_compare.py",   [],            "fusion category comparison"),
        ("visualize/viz_qtflow.py",    ["--compare"], "QtFlow timing comparison"),
    ]
    for script, extra_args, label in scripts:
        print(f"\nGenerating {label} ...")
        result = subprocess.run(
            [sys.executable, script] + extra_args,
            cwd=pipeline_dir,
        )
        if result.returncode != 0:
            print(f"  WARNING: {script} failed — check matplotlib installation")
        else:
            print(f"  {label}: done")
    print("\n  All figures saved to outputs/figures/")


def _gnn_argv(args, extra: list) -> list:
    """Build a sys.argv-style flag list shared by train/evaluate/viz_gnn,
    omitting --device when unset so each script falls back to its own
    cuda-if-available default rather than being forced to a literal "None".
    """
    argv = ["--model", args.model] + extra
    if args.device:
        argv += ["--device", args.device]
    return argv


def run_train_eval(args) -> None:
    """Train the Stage 6 GNN, evaluate the resulting checkpoint, and generate
    the associated figures — the full chain in one command instead of three
    manual invocations (see PIPELINE_LOG.md's Stage 6 verification recipe).
    """
    from stage6_train.train import main as train_main
    from stage6_train.evaluate import main as evaluate_main

    print(f"\n[train-eval] Stage 6a: training ({args.model}, split-mode={args.split_mode}) ...")
    train_argv = [
        "--epochs", str(args.epochs), "--lr", str(args.lr),
        "--batch-size", str(args.batch_size), "--seed", str(args.seed),
        "--patience", str(args.patience), "--split-mode", args.split_mode,
    ]
    if args.split_mode == "holdout":
        train_argv += ["--val-frac", str(args.val_frac), "--test-frac", str(args.test_frac)]
    elif args.split_mode == "kfold":
        train_argv += ["--k", str(args.k)]
    sys.argv = [sys.argv[0]] + _gnn_argv(args, train_argv)
    train_main()

    from visualize.viz_gnn import main as viz_main
    calibrate_flag = ["--calibrate"] if args.calibrate else []

    if args.split_mode == "holdout":
        folds = ["holdout"]
    elif args.split_mode == "kfold":
        folds = [f"fold{i}" for i in range(args.k)]
    else:
        folds = [None]

    for fold in folds:
        suffix = f" (fold={fold})" if fold else ""
        print(f"\n[train-eval] Stage 6b: evaluating{suffix} ...")
        fold_flag = ["--fold", fold] if fold else []
        sys.argv = [sys.argv[0]] + _gnn_argv(args, ["--thresh", str(args.thresh)] + fold_flag) + calibrate_flag
        evaluate_main()

        if args.split_mode == "kfold":
            continue  # combined figures generated once, after all folds are evaluated

        print(f"[train-eval] Stage 6c: generating figures{suffix} ...")
        sys.argv = [sys.argv[0], "--model", args.model, "--thresh", str(args.thresh)] + fold_flag
        viz_main()

    if args.split_mode == "kfold":
        print(f"\n[train-eval] Stage 6c: generating k-fold combined figures ({args.k} folds) ...")
        sys.argv = [sys.argv[0], "--model", args.model, "--thresh", str(args.thresh), "--kfold", str(args.k)]
        viz_main()


def check_sources() -> None:
    """Report every discovered design whose config has no taint sources.

    QtFlow (Stage 4) silently writes empty score files for designs with no
    `sources` — the only downstream symptom is a "no QtFlow scores" WARN in
    the comparison figures, long after a full --all run has already spent
    the time on them. Run this before --all to catch the gap up front.
    """
    designs = discover_designs()
    if not designs:
        print("No designs found in stage0_designs/TjIn/.")
        return

    missing = []
    for name in designs:
        try:
            cfg = get_design_config(name)
        except Exception as e:
            print(f"  ERROR: {name}: {e}")
            continue
        if not cfg.get("sources"):
            missing.append(name)

    print(f"Checked {len(designs)} designs.")
    if missing:
        print(f"\n{len(missing)} design(s) with NO taint sources "
              f"(QtFlow scoring will be skipped for these):")
        for name in missing:
            print(f"  - {name}")
        print("\nAdd a \"sources\" override for these in config/designs.json "
              "(e.g. copy from a working same-core HT-variant).")
    else:
        print("All designs have at least one configured taint source.")


def _is_stale(design: str) -> bool:
    """True if config/designs.json was edited after this design's last run.

    Without this, editing a `sources` override and re-running --all (without
    --force) silently leaves the old, wrong outputs in place — every stage
    checks only "does the output file exist", never "is it still current for
    today's config". combined_labels.json (Stage 5) is used as the
    last-run marker since it's written for every design that gets that far,
    unlike the Stage 6 hw2vec export which is skipped when sources are empty.
    """
    if not OVERRIDES_FILE.exists():
        return False
    combined = OUTPUTS_DIR / design / "combined_labels.json"
    if not combined.exists():
        return False
    return OVERRIDES_FILE.stat().st_mtime > combined.stat().st_mtime


def main():
    parser = argparse.ArgumentParser(
        description="IFT Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--design", metavar="NAME",
                       help="Run pipeline for a single design (e.g. AES-T2100)")
    group.add_argument("--all", action="store_true",
                       help="Run pipeline for all designs found in stage0_designs/")
    group.add_argument("--compare", action="store_true",
                       help="Generate cross-design comparison figures only")
    group.add_argument("--train", action="store_true",
                       help="Train Stage 6 GNN on hw2vec exports (dataset-wide)")
    group.add_argument("--train-eval", action="store_true",
                       help="Train, then evaluate, then generate GNN figures — one command "
                            "for the full Stage 6 train->evaluate->viz chain")
    group.add_argument("--check-sources", action="store_true",
                       help="List discovered designs with no taint sources configured "
                            "(would silently skip QtFlow scoring) and exit")

    parser.add_argument("--from-stage", type=int, default=1, metavar="N",
                        help="Resume from stage N (1-6, default: 1)")
    parser.add_argument("--force", action="store_true",
                        help="Recompute all stages even if outputs exist")
    parser.add_argument("--fsm", action="store_true",
                        help="Enable FSM state register detection in DFG taint")
    parser.add_argument("--tc-model", action="store_true",
                        help="Use GLRA Transmission Cost scoring in DFG taint")
    parser.add_argument("--variant", choices=["tjin", "tjfree"], default="tjin",
                        help="Run against trojan-inserted (default) or clean-baseline "
                             "TjFree sources (writes to outputs/<design>__tjfree/)")

    gnn_group = parser.add_argument_group(
        "Stage 6 GNN options (used by --train / --train-eval)")
    gnn_group.add_argument("--model", choices=["sage", "gcn"], default="sage",
                        help="GNN architecture (default: sage)")
    gnn_group.add_argument("--epochs", type=int, default=100)
    gnn_group.add_argument("--lr", type=float, default=1e-3)
    gnn_group.add_argument("--batch-size", type=int, default=4)
    gnn_group.add_argument("--seed", type=int, default=1337)
    gnn_group.add_argument("--device", default=None,
                        help="Defaults to cuda if available, else cpu (see stage6_train.train)")
    gnn_group.add_argument("--patience", type=int, default=10)
    gnn_group.add_argument("--split-mode", choices=["random", "holdout", "kfold"], default="random",
                        help="'random': fixed-seed 80/20 split, no held-out test set. "
                             "'holdout': fixed-seed 3-way split (default 60/20/20, see "
                             "--val-frac/--test-frac) with a genuinely held-out test set. "
                             "'kfold': k-fold CV, randomly partitioned at the design level "
                             "(see --k).")
    gnn_group.add_argument("--val-frac", type=float, default=0.2,
                        help="Validation fraction for --split-mode holdout (default: 0.2)")
    gnn_group.add_argument("--test-frac", type=float, default=0.2,
                        help="Held-out test fraction for --split-mode holdout (default: 0.2)")
    gnn_group.add_argument("--k", type=int, default=5,
                        help="Number of folds for --split-mode kfold (default: 5)")
    gnn_group.add_argument("--thresh", type=float, default=0.5,
                        help="Decision threshold for evaluation/figures (default: 0.5)")
    gnn_group.add_argument("--calibrate", action="store_true",
                        help="Also sweep per-design F1-maximizing thresholds during evaluation")

    args = parser.parse_args()

    if not any([args.design, args.all, args.compare, args.train, args.train_eval, args.check_sources]):
        parser.print_help()
        sys.exit(0)

    if args.check_sources:
        check_sources()
        return

    if args.compare:
        run_compare()
        return

    if args.train:
        from stage6_train.train import main as train_main
        train_argv = [
            "--epochs", str(args.epochs), "--lr", str(args.lr),
            "--batch-size", str(args.batch_size), "--seed", str(args.seed),
            "--patience", str(args.patience), "--split-mode", args.split_mode,
        ]
        if args.split_mode == "holdout":
            train_argv += ["--val-frac", str(args.val_frac), "--test-frac", str(args.test_frac)]
        elif args.split_mode == "kfold":
            train_argv += ["--k", str(args.k)]
        sys.argv = [sys.argv[0]] + _gnn_argv(args, train_argv)
        train_main()
        return

    if args.train_eval:
        run_train_eval(args)
        return

    if args.all:
        designs = discover_designs()
    else:
        designs = [args.design]
    if not designs:
        print("No designs found. Drop design folders into "
              "stage0_designs/TjIn/ (and optionally stage0_designs/TjFree/) first.")
        sys.exit(1)

    print(f"Running pipeline for: {designs}")
    print(f"From stage: {args.from_stage}  |  Force: {args.force}  |  "
          f"FSM: {args.fsm}  |  TC-model: {args.tc_model}")

    failed = []
    skipped = []
    for name in designs:
        force = args.force
        if not force and _is_stale(name):
            print(f"\n  {name}: config/designs.json changed since last run — forcing recompute")
            force = True
        result = run_design(name, from_stage=args.from_stage,
                            force=force, fsm=args.fsm, tc_model=args.tc_model,
                            variant=args.variant)
        if result is False:
            failed.append(name)
        elif result is None:
            skipped.append(name)

    print(f"\n{'='*60}")
    succeeded = [d for d in designs if d not in skipped and d not in failed]
    if skipped:
        print(f"SKIPPED (unsupported): {skipped}")
    if failed:
        print(f"FAILED: {failed}")
    print(f"SUCCESS: {succeeded}")

    # Comparison figures assume tjin variant — skip for tjfree runs. Still
    # worth generating over whatever succeeded even if some designs failed —
    # one bad design shouldn't block figures for the rest of the corpus.
    if args.all and args.variant == "tjin" and succeeded:
        run_compare()

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
