"""
stage6_train/model.py — GraphSAGE (primary) + GCN (baseline) for node-level
binary trojan classification on the 14-dim IFT feature vector.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, GCNConv


class GraphSAGEClassifier(nn.Module):
    def __init__(self, in_dim: int = 14, hidden: int = 64, dropout: float = 0.3):
        super().__init__()
        self.conv1 = SAGEConv(in_dim, hidden)
        self.conv2 = SAGEConv(hidden, hidden)
        self.conv3 = SAGEConv(hidden, hidden)
        self.head  = nn.Linear(hidden, 1)
        self.dropout = dropout

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = F.relu(self.conv2(x, edge_index))
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = F.relu(self.conv3(x, edge_index))
        return self.head(x).squeeze(-1)


class GCNClassifier(nn.Module):
    def __init__(self, in_dim: int = 14, hidden: int = 64, dropout: float = 0.3):
        super().__init__()
        self.conv1 = GCNConv(in_dim, hidden)
        self.conv2 = GCNConv(hidden, hidden)
        self.head  = nn.Linear(hidden, 1)
        self.dropout = dropout

    def forward(self, x, edge_index):
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = F.relu(self.conv2(x, edge_index))
        return self.head(x).squeeze(-1)


def build_model(name: str, in_dim: int = 14):
    name = name.lower()
    if name == "sage":
        return GraphSAGEClassifier(in_dim=in_dim)
    if name == "gcn":
        return GCNClassifier(in_dim=in_dim)
    raise ValueError(f"unknown model: {name}")
