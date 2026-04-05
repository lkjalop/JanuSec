import os
import time
from src.graph.hopgraph import HopGraph


def test_hard_watermark_pruning(monkeypatch, tmp_path):
    # create a HopGraph with small hard watermark
    hg = HopGraph()
    # force small hard watermark via env override
    monkeypatch.setenv('HOPGRAPH_HARD_EDGE_WM', '10')
    # Recreate to pick env
    hg = HopGraph()

    # Insert 20 edges with increasing timestamps
    base = time.time()
    for i in range(20):
        hg.add_edge('host:hw', f'process:p{i}', 'runs', source='event', ts=base + i)

    total_edges = sum(len(v) for v in hg.adj.values())
    # After insertion and watermark check, total_edges should be <= hard watermark (approx 75% kept)
    hard = hg.hard_edge_watermark or 0
    assert total_edges <= max(1, int(0.75 * 20))
