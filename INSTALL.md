# Installation

DRIFT needs two things: **Python 3.9+** with a handful of pip packages, and
**Yosys** (the open-source RTL synthesis tool), which is a native binary,
not a Python package. This guide covers all three major platforms.

If you just want the fastest path and don't care which method installs
Yosys, use the **OSS CAD Suite** section below — it's the one method that
works identically on Windows, macOS, and Linux.

- [1. Python packages (all platforms)](#1-python-packages-all-platforms)
- [2. Yosys](#2-yosys)
  - [Option A — OSS CAD Suite (recommended, all platforms)](#option-a--oss-cad-suite-recommended-all-platforms)
  - [Option B — Linux native package](#option-b--linux-native-package)
  - [Option C — macOS (Homebrew)](#option-c--macos-homebrew)
  - [Option D — Windows (WSL2)](#option-d--windows-wsl2)
  - [Option E — conda-forge (any OS)](#option-e--conda-forge-any-os)
- [3. Verify the install](#3-verify-the-install)
- [4. Optional: GNN training (Stage 6)](#4-optional-gnn-training-stage-6)
- [Troubleshooting](#troubleshooting)

---

## 1. Python packages (all platforms)

Requires Python 3.9 or newer.

```bash
# from the repository root
python3 -m venv .venv

# activate it:
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows (cmd.exe)
.venv\Scripts\Activate.ps1       # Windows (PowerShell)

pip install -r requirements.txt
```

`requirements.txt` installs: `numpy`, `matplotlib`, `seaborn`, `pyverilog`.
These are pure-Python or have prebuilt wheels for Windows/macOS/Linux, so
`pip install` alone is sufficient — no compiler needed.

## 2. Yosys

Yosys does the gate-level synthesis in Stage 1. It's a separate,
native-code tool — pick **one** of the options below.

### Option A — OSS CAD Suite (recommended, all platforms)

[YosysHQ's OSS CAD Suite](https://github.com/YosysHQ/oss-cad-suite-build)
ships prebuilt, self-contained Yosys binaries for Linux (x64/arm64), macOS
(x64/arm64), and Windows (x64) — the same tarball/zip mechanism on every OS,
no package manager or admin rights required.

1. Download the latest release for your OS/architecture from the
   [oss-cad-suite-build releases page](https://github.com/YosysHQ/oss-cad-suite-build/releases).
2. Extract it anywhere, e.g. `~/oss-cad-suite` or `C:\oss-cad-suite`.
3. Add its `bin/` directory to your `PATH`:

   ```bash
   # Linux / macOS (add to ~/.bashrc or ~/.zshrc to persist):
   export PATH="$HOME/oss-cad-suite/bin:$PATH"
   ```

   ```powershell
   # Windows (PowerShell), current session only:
   $env:PATH = "C:\oss-cad-suite\bin;" + $env:PATH
   # To persist, add that path via System Properties → Environment Variables,
   # or run once: setx PATH "C:\oss-cad-suite\bin;%PATH%"
   ```

4. Confirm: `yosys -V` should print a version string.

### Option B — Linux native package

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install yosys

# Fedora
sudo dnf install yosys

# Arch
sudo pacman -S yosys
```

Distro-packaged Yosys versions lag upstream; if a pipeline stage behaves
unexpectedly, try Option A before filing a bug.

### Option C — macOS (Homebrew)

```bash
brew install yosys
```

### Option D — Windows (WSL2)

If you'd rather work in a Linux userspace on Windows:

```powershell
wsl --install          # once, then reboot if prompted
```

Then inside the WSL2 Ubuntu shell, follow the **Linux native package**
steps above (Option B), and run the rest of this guide (`pip install`,
`python3 run_pipeline.py ...`) from within WSL2 too — keep the whole
toolchain on one side of the Windows/Linux boundary to avoid path
translation issues.

### Option E — conda-forge (any OS)

If you already use conda/mamba:

```bash
conda install -c conda-forge yosys
```

### Graphviz (optional)

Not required by the automated pipeline — nothing in this codebase invokes
`dot`/`graphviz` at runtime. It's only useful if you want to manually
visualize a synthesized netlist via Yosys's own `show` command
(`yosys -p "read_verilog ...; show"`). If you want it:

```bash
sudo apt install graphviz      # Debian/Ubuntu
brew install graphviz          # macOS
choco install graphviz         # Windows (Chocolatey)
conda install -c conda-forge graphviz   # any OS
```

## 3. Verify the install

```bash
yosys -V
python3 -c "import pyverilog; print('pyverilog OK')"
python3 -c "import numpy, matplotlib, seaborn; print('core deps OK')"
```

Then, from the repository root:

```bash
python3 run_pipeline.py --check-sources
```

This is a fast, read-only check — it does not run synthesis. An empty or
sane-looking list here means your environment is set up correctly.

## 4. Optional: GNN training (Stage 6)

Stage 6 (training a node classifier on the Stage 5 exports) needs PyTorch
and PyTorch Geometric, which are much larger and more platform-sensitive
than the core dependencies — install them separately, only if you plan to
run `--train` / `--train-eval`:

```bash
pip install -r requirements-train.txt
```

`torch` and `torch-geometric` publish CPU wheels for all three OSes via
plain `pip install`. If you have an NVIDIA GPU and want CUDA acceleration,
follow the selector at <https://pytorch.org/get-started/locally/> to get
the right `torch` build for your CUDA version *before* installing
`requirements-train.txt` (pip will otherwise install the CPU-only build).

## Troubleshooting

**`yosys: command not found` / `'yosys' is not recognized`**
Yosys isn't on your `PATH`. Re-check step 2 — most commonly, the OSS CAD
Suite `bin/` directory wasn't added to `PATH` in the *current* shell
session (re-open your terminal after editing `~/.bashrc`, or re-run the
`setx`/`$env:PATH` line above).

**`ModuleNotFoundError: No module named 'pyverilog'`**
Your virtual environment isn't activated, or `pip install -r
requirements.txt` didn't complete. Re-run step 1 inside the activated venv.

**Yosys synthesis times out or fails on a large design**
`stage1_extract/run_yosys.py` runs Yosys with a 120-second timeout. For
unusually large designs, this is a code change, not a config option —
open an issue if you hit it.

**Windows: paths with spaces**
If you cloned the repo into a path containing spaces (e.g. under `OneDrive`
folders with spaces), quote paths in any command you type manually. The
pipeline itself uses `pathlib`/`subprocess` argument lists internally, so
it does not require shell quoting on its own.
