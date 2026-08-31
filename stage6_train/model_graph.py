"""
stage6_train/model_graph.py — GraphSAGE + global_mean_pool for graph-level
clean(TjFree)-vs-trojan(TjIn) classification on the 14-dim IFT feature vector.

Sketch matches the reviewer-doc's DualRepGraphClassifier proposal (see
"vault for testing/Future work to Do evaluations.md") — reused rather than
rewritten from scratch.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, global_mean_pool


class GraphSAGEGraphClassifier(nn.Module):
    def __init__(self, in_dim: int = 14, hidden: int = 64, dropout: float = 0.3):
        super().__init__()
        self.conv1 = SAGEConv(in_dim, hidden)
        self.conv2 = SAGEConv(hidden, hidden)
        self.conv3 = SAGEConv(hidden, hidden)
        self.head  = nn.Linear(hidden, 1)
        self.dropout = dropout

    def forward(self, x, edge_index, batch):
        x = F.relu(self.conv1(x, edge_index))
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = F.relu(self.conv2(x, edge_index))
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = F.relu(self.conv3(x, edge_index))
        graph_embedding = global_mean_pool(x, batch)
        return self.head(graph_embedding).squeeze(-1)


def build_graph_model(in_dim: int = 14):
    return GraphSAGEGraphClassifier(in_dim=in_dim)
