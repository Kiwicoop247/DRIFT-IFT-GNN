"""
stage6_train/dataset.py — IFTNodeDataset

Loads each design's hw2vec/{node_features,edge_index,labels}.npy into a
torch_geometric.data.Data object. Designs without a hw2vec/ subdir are skipped.
"""

import sys
import json
import random
from pathlib import Path

import numpy as np
import torch
from torch_geometric.data import Data

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.pipeline_config import discover_designs, OUTPUTS_DIR

def _load_design(design: str):
    d = OUTPUTS_DIR / design / "hw2vec"
    if not d.is_dir():
        return None
    try:
        x  = np.load(d / "node_features.npy")
        ei = np.load(d / "edge_index.npy")
        y  = np.load(d / "labels.npy")
    except FileNotFoundError:
        return None
    if x.shape[0] == 0:
        return None
    data = Data(
        x=torch.from_numpy(x).float(),
        edge_index=torch.from_numpy(ei).long(),
        y=torch.from_numpy(y).float(),
    )
    data.design_name = design
    data.num_nodes = x.shape[0]
    return data


class IFTNodeDataset:
    """Container for a list of per-design Data objects (no PyG InMemoryDataset)."""

    def __init__(self, designs=None):
        designs = designs if designs is not None else discover_designs()
        self.data_list = []
        self.skipped = []
        for name in designs:
            d = _load_design(name)
            if d is None:
                self.skipped.append(name)
            else:
                self.data_list.append(d)

    def __len__(self):
        return len(self.data_list)

    def split(self, val_frac: float = 0.2, seed: int = 1337):
        """Deterministic 80/20 design-level split."""
        rng = random.Random(seed)
        idx = list(range(len(self.data_list)))
        rng.shuffle(idx)
        n_val = max(1, int(round(len(idx) * val_frac)))
        val_idx = set(idx[:n_val])
        train, val = [], []
        for i, d in enumerate(self.data_list):
            (val if i in val_idx else train).append(d)
        return train, val

    def split3(self, val_frac: float = 0.2, test_frac: float = 0.2, seed: int = 1337):
        """Deterministic design-level 3-way split (default 60/20/20).

        Unlike split() (train/val only), the test partition here is held out
        entirely — never touched by training or by the early-stopping/
        checkpoint-selection loop that watches val — so its metrics
        (evaluate.py's "unseen" split) are a true generalization estimate,
        not one that's already been used to pick the checkpoint.
        """
        rng = random.Random(seed)
        idx = list(range(len(self.data_list)))
        rng.shuffle(idx)
        n = len(idx)
        n_val  = max(1, int(round(n * val_frac)))  if val_frac  > 0 else 0
        n_test = max(1, int(round(n * test_frac))) if test_frac > 0 else 0
        n_train = n - n_val - n_test
        if n_train < 1:
            raise ValueError(
                f"val_frac={val_frac} + test_frac={test_frac} leaves no training "
                f"designs out of {n} total — reduce one or both fractions"
            )
        val_idx  = set(idx[:n_val])
        test_idx = set(idx[n_val:n_val + n_test])
        train, val, test = [], [], []
        for i, d in enumerate(self.data_list):
            if i in val_idx:
                val.append(d)
            elif i in test_idx:
                test.append(d)
            else:
                train.append(d)
        return train, val, test

    def kfold_splits(self, k: int = 5, seed: int = 1337):
        """k-fold CV at the design level, randomly partitioned — yields
        (train, val, fold_name) for each of the k folds, fold_name being
        "fold0".."fold{k-1}". Every design is used for validation exactly
        once across the k folds.
        """
        rng = random.Random(seed)
        idx = list(range(len(self.data_list)))
        rng.shuffle(idx)
        folds = [idx[i::k] for i in range(k)]  # round-robin spreads any remainder evenly
        for fold_i, val_idx_list in enumerate(folds):
            val_idx = set(val_idx_list)
            train, val = [], []
            for i, d in enumerate(self.data_list):
                (val if i in val_idx else train).append(d)
            if not val or not train:
                continue
            yield train, val, f"fold{fold_i}"

    def pos_weight(self, subset=None) -> torch.Tensor:
        """neg/pos ratio across the given subset (default: full dataset)."""
        subset = subset if subset is not None else self.data_list
        pos = sum(int(d.y.sum().item()) for d in subset)
        tot = sum(d.num_nodes for d in subset)
        neg = tot - pos
        ratio = (neg / pos) if pos > 0 else 1.0
        return torch.tensor([ratio], dtype=torch.float32)


def _load_design_variant(design: str, variant: str):
    output_name = f"{design}__tjfree" if variant == "tjfree" else design
    d = OUTPUTS_DIR / output_name / "hw2vec"
    if not d.is_dir():
        return None
    try:
        x  = np.load(d / "node_features.npy")
        ei = np.load(d / "edge_index.npy")
        gl = np.load(d / "graph_label.npy")
    except FileNotFoundError:
        return None
    if x.shape[0] == 0:
        return None
    data = Data(
        x=torch.from_numpy(x).float(),
        edge_index=torch.from_numpy(ei).long(),
        y=torch.from_numpy(gl).float(),
    )
    data.design_name = design
    data.variant = variant
    data.num_nodes = x.shape[0]
    return data


class IFTGraphDataset:
    """Graph-level clean(TjFree)-vs-trojan(TjIn) classification dataset.

    Loads BOTH variants per design (where both hw2vec/ exports exist) — each
    design contributes up to 2 graphs: one labelled 0 (TjFree), one labelled 1
    (TjIn). Requires `run_pipeline.py --variant tjfree` to have been run first;
    designs missing a tjfree export are silently skipped (see .skipped)."""

    def __init__(self, designs=None):
        designs = designs if designs is not None else discover_designs()
        self.data_list = []
        self.skipped = []
        for name in designs:
            for variant in ("tjin", "tjfree"):
                d = _load_design_variant(name, variant)
                if d is None:
                    self.skipped.append(f"{name}:{variant}")
                else:
                    self.data_list.append(d)

    def __len__(self):
        return len(self.data_list)

    def split(self, val_frac: float = 0.2, seed: int = 1337):
        """Deterministic 80/20 split BY DESIGN (both variants of a design stay
        on the same side) — otherwise the model could see a design's TjIn
        graph in training and its near-identical TjFree twin in validation,
        leaking structure rather than testing generalization."""
        rng = random.Random(seed)
        names = sorted({d.design_name for d in self.data_list})
        rng.shuffle(names)
        n_val = max(1, int(round(len(names) * val_frac)))
        val_names = set(names[:n_val])
        train, val = [], []
        for d in self.data_list:
            (val if d.design_name in val_names else train).append(d)
        return train, val

    def pos_weight(self, subset=None) -> torch.Tensor:
        subset = subset if subset is not None else self.data_list
        pos = sum(int(d.y.item()) for d in subset)
        neg = len(subset) - pos
        ratio = (neg / pos) if pos > 0 else 1.0
        return torch.tensor([ratio], dtype=torch.float32)


if __name__ == "__main__":
    ds = IFTNodeDataset()
    print(f"loaded {len(ds)} designs, skipped {len(ds.skipped)}: {ds.skipped}")
    tr, va = ds.split()
    print(f"train={len(tr)} val={len(va)}  pos_weight(train)={ds.pos_weight(tr).item():.2f}")
    for d in ds.data_list[:3]:
        print(f"  {d.design_name:20s} N={d.num_nodes:5d}  E={d.edge_index.shape[1]:5d}  pos={int(d.y.sum())}")

    print()
    gds = IFTGraphDataset()
    print(f"graph dataset: loaded {len(gds)} graphs, skipped {len(gds.skipped)}: {gds.skipped}")
    gtr, gva = gds.split()
    print(f"graph train={len(gtr)} val={len(gva)}  pos_weight={gds.pos_weight(gtr).item():.2f}")
