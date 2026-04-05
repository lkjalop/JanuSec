import json
import tempfile
import os
from src.graph.hopgraph import HopGraph


def test_snapshot_plus_wal_additive(tmp_path):
    # Prepare paths
    wal = str(tmp_path / 'hop_wal.jsonl')
    snap = str(tmp_path / 'hop_snapshot.json')

    # Build a snapshot containing initial edges
    initial_nodes = {
        'host:1': {'id': 'host:1'},
        'proc:a': {'id': 'proc:a'},
    }
    initial_adj = {
        'host:1': [('proc:a', 'runs', 1000.0, 'event', 1.0)]
    }
    snap_data = {'nodes': initial_nodes, 'adj': initial_adj, 'saved_ts': 1000.0}
    with open(snap, 'w', encoding='utf-8') as fh:
        fh.write(json.dumps(snap_data))

    # Create WAL file containing only extra entries to be replayed
    extra_op = {'op': 'edge', 'src': 'proc:a', 'dst': 'ip:1.2.3.4', 'etype': 'connects_to', 'srcv': 'event', 'ts': 2000.0, 'attrs': {}, 'w': 1.0}
    with open(wal, 'w', encoding='utf-8') as fw:
        fw.write(json.dumps(extra_op) + '\n')

    # Load into fresh HopGraph and assert combined adjacency
    hg = HopGraph(wal_path=wal, snapshot_path=snap)
    hg.load_snapshot()

    # Expect initial edge present
    assert 'host:1' in hg.adj
    assert any(e[0] == 'proc:a' and e[1] == 'runs' for e in hg.adj.get('host:1', []))
    # Expect extra edge from WAL replay
    assert 'proc:a' in hg.adj
    assert any(e[0] == 'ip:1.2.3.4' and e[1] == 'connects_to' for e in hg.adj.get('proc:a', []))
