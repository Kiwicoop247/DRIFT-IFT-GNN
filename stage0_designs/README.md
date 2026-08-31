# stage0_designs/

This is the pipeline's sole design intake folder. It ships empty — drop your
own Verilog here to analyze it.

```
stage0_designs/
├── TjIn/<DESIGN_NAME>/*.v     # required: trojan-inserted (or just plain) RTL sources
└── TjFree/<DESIGN_NAME>/*.v   # optional: clean baseline of the same design
```

- `<DESIGN_NAME>` becomes the name you pass to `--design <DESIGN_NAME>`, and
  is picked up automatically by `--all`.
- The pipeline trusts this `TjIn`/`TjFree` split as given — it does not try
  to auto-detect which files are trojan-inserted vs. clean. Everything under
  `TjIn/<name>/` is treated as the design to analyze; the golden
  ("what would this look like without a Trojan") baseline is computed by
  *masking* Trojan cells out of the synthesized `TjIn` netlist, not by
  re-synthesizing `TjFree/`. `TjFree/` is only used by the optional
  graph-level clean-vs-trojan classification path (`--variant tjfree`).
- Sources, sinks (outputs), and Trojan-signal patterns are auto-detected by
  scanning signal names (see `config/pipeline_config.py`). If detection gets
  it wrong for your design — commonly, a non-crypto peripheral where no port
  name matches `key|state|plaintext|secret` — add an override in
  `config/designs.json`. Run `python3 run_pipeline.py --check-sources` to
  find designs that need one.

## Where to get sample designs

This repository does not bundle any sample RTL. If you want a ready-made
corpus of trojan-inserted benchmarks to try the pipeline against,
[Trust-Hub](https://trust-hub.org) is the standard academic source — check
their terms before redistributing any of their designs yourself.
