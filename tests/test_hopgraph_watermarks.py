from __future__ import annotations
import os
from src.graph.hopgraph import HopGraph


def test_hopgraph_hard_watermark_prune(monkeypatch):
    # Configure small hard watermark
    monkeypatch.setenv('HOPGRAPH_HARD_EDGE_WM','50')
    g = HopGraph(wal_path='data/test_wal.log', snapshot_path='data/test_snap.json')
    # Add edges exceeding hard watermark; edges are per host->process
    for i in range(120):
        g.add_edge(f'host:{i//2}', f'process:p{i}', 'runs', source='event')
    total_edges = sum(len(v) for v in g.adj.values())
    # After auto trim, total edges should be <= about 75% of pre-trim or <= hard watermark * some factor
    assert total_edges <= 90, f"Unexpected remaining edges {total_edges}"
    # Add again to trigger another prune cycle
    for i in range(60):
        g.add_edge(f'host:x{i//2}', f'process:q{i}', 'runs', source='event')
    total_edges2 = sum(len(v) for v in g.adj.values())
    assert total_edges2 <= 140
