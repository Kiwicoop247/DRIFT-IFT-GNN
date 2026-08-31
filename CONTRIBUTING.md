# Contributing to DRIFT

Thanks for considering a contribution. This project grew out of a Master's
thesis, so the code prioritizes being explainable and reproducible over
being maximally general — please keep that spirit in mind.

## Before you start

- For anything beyond a small fix, open an issue first to discuss the
  approach. This avoids wasted work on a PR that doesn't fit the project's
  direction.
- Read [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — it explains
  *why* the code is structured the way it is (Yosys flattening order, the
  DFG/AST split, ghost nodes, scoring weights). A lot of "obvious"
  simplifications turn out to break a specific detection case documented
  there.

## Development setup

Follow [`INSTALL.md`](INSTALL.md) to get Yosys and the Python dependencies
installed, then:

```bash
python3 run_pipeline.py --check-sources     # fast sanity check
python3 run_pipeline.py --design <a-design-you-have-locally>
```

There is no bundled sample corpus (see the README's "Bringing your own
designs" section) — you'll need at least one Verilog design under
`stage0_designs/TjIn/<NAME>/` to exercise the pipeline end to end.

## Making changes

- Match the existing code style (plain functions over classes, `pathlib`
  over string path concatenation, no dependency beyond what's already in
  `requirements.txt` / `requirements-train.txt` unless the PR justifies it).
- If you change a scoring formula or taint-propagation rule, update
  [`docs/GUIDE.md`](docs/GUIDE.md) and, if the *reasoning* changes, add an
  entry to [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — future
  readers (including thesis reviewers) rely on that log to understand why
  the code looks the way it does.
- Keep platform portability in mind: no hardcoded absolute paths, no
  POSIX-only shell syntax in `subprocess` calls, no assumption that a tool
  other than Yosys itself is on `PATH`.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your change, with a clear description of what it fixes/adds and
   why.
3. Run the pipeline against at least one design and confirm
   `combined_labels.json` / `fusion_report.txt` still look sane for it.
4. Open the PR against `main`, referencing any related issue.

## Reporting bugs

Open an issue with:
- The command you ran.
- The full error output.
- Your OS, Python version, and Yosys version (`yosys -V`).
- If it's a detection-quality issue (e.g. a signal scored unexpectedly),
  the design name and which category/score you expected vs. got.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). By
participating, you're expected to uphold it.
