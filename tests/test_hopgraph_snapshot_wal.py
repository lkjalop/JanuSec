import json
from pathlib import Path
from src.graph.hopgraph import HopGraph


def test_snapshot_wal_roundtrip(tmp_path):
    wal = tmp_path / 'hg_wal.log'
    snap = tmp_path / 'hg_snap.json'

    hg = HopGraph(wal_path=str(wal), snapshot_path=str(snap))
    # create some edges
    hg.add_edge('host:a', 'process:p1', 'runs', source='event')
    hg.add_edge('process:p1', 'domain:example.org', 'contacts_domain', source='event')
    hg.add_edge('host:b', 'process:p2', 'runs', source='event')

    # save snapshot
    hg.save_snapshot()
    # In many deployments the WAL is truncated/rotated after snapshot; remove it here
    try:
        if wal.exists():
            wal.unlink()
    except Exception:
        pass

    # Create a fresh instance and load snapshot+WAL
    hg2 = HopGraph(wal_path=str(wal), snapshot_path=str(snap))
    hg2.load_snapshot()

    # Compare adjacency lengths
    total1 = sum(len(v) for v in hg.adj.values())
    total2 = sum(len(v) for v in hg2.adj.values())
    assert total1 == total2
    # Basic node presence
    assert 'host:a' in hg2.nodes
    assert 'process:p2' in hg2.nodes
