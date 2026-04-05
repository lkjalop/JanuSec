import json, time
from graph.hopgraph import HopGraph, DEFAULT_SOURCE_WEIGHTS

def test_hopgraph_load_legacy_snapshot(tmp_path):
    # Legacy snapshot with 4-tuple edges (dst, etype, ts, source) no weight
    snap = tmp_path / 'legacy_snap.json'
    ts = time.time() - 100
    legacy = {
        'nodes': {'host:a': {'id':'host:a'}, 'ip:1.2.3.4': {'id':'ip:1.2.3.4'}},
        'adj': {
            'host:a': [["ip:1.2.3.4", "conn", ts, "event"]]
        },
        'saved_ts': time.time()
    }
    snap.write_text(json.dumps(legacy), encoding='utf-8')
    hg = HopGraph(wal_path=str(tmp_path / 'wal.log'), snapshot_path=str(snap))
    hg.load_snapshot()
    edges = hg.adj.get('host:a')
    assert edges and len(edges[0]) == 5  # weight appended
    # Weight should default from source weights mapping
    assert abs(edges[0][4] - DEFAULT_SOURCE_WEIGHTS['event']) < 1e-6
