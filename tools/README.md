# tools/

Standalone scripts that operate on already-generated `outputs/<DESIGN>/`
data rather than being part of the main `run_pipeline.py` orchestration.

- **`ablation_weights.py`** — recomputes per-signal scores under ±0.1
  perturbations of each QFlow/QtFlow weight, using the Stage 2/3 component
  values already written to `outputs/<DESIGN>/`. Does not re-run synthesis
  or taint propagation. Run after the main pipeline has produced outputs
  for at least one design:

  ```bash
  python3 tools/ablation_weights.py
  ```
