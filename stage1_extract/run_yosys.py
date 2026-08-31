"""
stage1_extract/run_yosys.py — Yosys synthesis (Stage 1: DFG extraction)

Synthesises a design's TjIn Verilog source files into a flattened gate-level
JSON netlist that the DFG taint engine (stage2_ift/dfg_taint.py) reads.

Usage:
    python3 stage1_extract/run_yosys.py --design AES-T2100
    python3 stage1_extract/run_yosys.py --design AES-T2300 --keep-hierarchy
    python3 stage1_extract/run_yosys.py --all
"""

import sys
import os
import re
import shutil
import argparse
import subprocess
import tempfile
import json
from pathlib import Path

# Allow imports from pipeline root
sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import get_design_config, discover_designs, get_output_path


# Matches `include "any/path/file.h" in Verilog
_INCLUDE_RE = re.compile(r'(`include\s+")([^"]+)(")')


def _patch_includes(verilog_dir: Path, verilog_files: list, tmpdir: Path) -> Path:
    """
    Copy Verilog source files to tmpdir, rewriting any `include paths that
    point to non-existent absolute locations to just the bare filename so that
    Yosys (run from tmpdir) can find the header locally.

    Header files (*.h) are always copied alongside the patched sources.
    Returns the (possibly unchanged) tmpdir Path.
    """
    needs_patch = False

    # First pass: check whether any file has a broken include
    for fname in verilog_files:
        text = (verilog_dir / fname).read_text(encoding='utf-8', errors='ignore')
        for m in _INCLUDE_RE.finditer(text):
            inc_path = Path(m.group(2))
            if inc_path.is_absolute() and not inc_path.exists():
                needs_patch = True
                break
        if needs_patch:
            break

    if not needs_patch:
        return verilog_dir   # nothing to do — use original dir

    # Copy all headers first so patched sources can reference them
    for hdr in verilog_dir.glob("*.h"):
        shutil.copy2(hdr, tmpdir / hdr.name)

    # Second pass: copy and patch each source file
    for fname in verilog_files:
        src_text = (verilog_dir / fname).read_text(encoding='utf-8', errors='ignore')

        def _fix(m):
            inc_path = Path(m.group(2))
            if inc_path.is_absolute() and not inc_path.exists():
                local = verilog_dir / inc_path.name
                if local.exists():
                    return m.group(1) + str(local) + m.group(3)
            return m.group(0)

        patched = _INCLUDE_RE.sub(_fix, src_text)
        (tmpdir / fname).write_text(patched)

    return tmpdir


def build_yosys_script(cfg: dict, verilog_dir: Path, output_json: Path,
                       keep_hierarchy: bool = False) -> str:
    """Generate a Yosys synthesis script string for the given design config."""
    files = " ".join(
        str(verilog_dir / f) for f in cfg["verilog_files"]
    )
    top = cfg["top_module"]

    # Per-design signals to preserve before flatten removes them as dead logic
    # (critical for T2100 power-side-channel: SECRETKey, LEAKBit, INV chain, etc.)
    keep_signals = cfg.get("keep_signals", [])
    keep_lines = [f"setattr -set keep 1 w:*{sig}*" for sig in keep_signals]

    lines = [
        f"read_verilog -sv {files}",
        f"hierarchy -top {top}",
        "proc",
        *keep_lines,             # mark Trojan signals before flatten
        "flatten" if not keep_hierarchy else "",
        "opt_clean",
        f"write_json {output_json}",
    ]
    return "\n".join(l for l in lines if l)


def run_synthesis(design_name: str, keep_hierarchy: bool = False, force: bool = False,
                   variant: str = "tjin") -> Path:
    """
    Run Yosys synthesis for a design.
    Returns path to the generated netlist.json.
    Skips if output already exists unless force=True.
    """
    cfg = get_design_config(design_name, variant=variant)
    output_dir = Path(cfg["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    output_json = output_dir / "netlist.json"

    if output_json.exists() and not force:
        print(f"[{design_name}] netlist.json already exists — skipping (use --force to rerun)")
        return output_json

    print(f"[{design_name}] Synthesising with Yosys (top module: {cfg['top_module']})...")

    verilog_dir = Path(cfg["verilog_dir"])
    tmpdir_obj = tempfile.TemporaryDirectory(prefix=f"{design_name}_src_")
    tmpdir = Path(tmpdir_obj.name)

    try:
        # Patch broken absolute `include paths (e.g. Trust-Hub designs from other machines)
        src_dir = _patch_includes(verilog_dir, cfg["verilog_files"], tmpdir)

        script = build_yosys_script(cfg, src_dir, output_json, keep_hierarchy)

        result = subprocess.run(
            ["yosys", "-p", script],
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        tmpdir_obj.cleanup()

    if result.returncode != 0:
        print(f"[{design_name}] Yosys FAILED:")
        print(result.stderr[-3000:])   # last 3KB of stderr
        raise RuntimeError(f"Yosys synthesis failed for {design_name}")

    if not output_json.exists():
        raise RuntimeError(f"Yosys ran but {output_json} was not created")

    # Quick validation — check cell count
    with open(output_json) as f:
        netlist = json.load(f)
    modules = netlist.get("modules", {})
    total_cells = sum(len(m.get("cells", {})) for m in modules.values())
    total_nets  = sum(len(m.get("netnames", {})) for m in modules.values())
    print(f"[{design_name}] Synthesis complete: {len(modules)} module(s), "
          f"{total_cells} cells, {total_nets} named nets → {output_json}")

    return output_json


def main():
    parser = argparse.ArgumentParser(description="Stage 1: Yosys synthesis → netlist.json")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--design", metavar="NAME",
                       help="Design name (e.g. AES-T2100)")
    group.add_argument("--all", action="store_true",
                       help="Run synthesis for all discovered designs")
    parser.add_argument("--keep-hierarchy", action="store_true",
                        help="Skip flatten step (keep module hierarchy in netlist)")
    parser.add_argument("--force", action="store_true",
                        help="Rerun even if output already exists")
    args = parser.parse_args()

    designs = discover_designs() if args.all else [args.design]

    errors = []
    for name in designs:
        try:
            run_synthesis(name, keep_hierarchy=args.keep_hierarchy, force=args.force)
        except Exception as e:
            print(f"[{name}] ERROR: {e}")
            errors.append(name)

    if errors:
        print(f"\nFailed designs: {errors}")
        sys.exit(1)


if __name__ == "__main__":
    main()
