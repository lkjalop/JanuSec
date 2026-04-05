import tempfile
import json
import os
from src.graph.hopgraph import HopGraph


def test_hopgraph_snapshot_roundtrip(tmp_path):
    wal = str(tmp_path / 'wal.log')
    snap = str(tmp_path / 'snap.json')
    hg = HopGraph(wal_path=wal, snapshot_path=snap)
    # add nodes/edges
    hg.add_node_attr('email:alice@example.com', type='email')
    hg.add_node_attr('user:alice', type='user')
    hg.add_edge('email:alice@example.com', 'user:alice', 'sent_to')

    # save snapshot to its configured snapshot_path
    hg.save_snapshot()

    # Confirm snapshot file exists and contains the nodes we saved
    import json as _json
    assert os.path.exists(snap)
    with open(snap, 'r', encoding='utf-8') as fh:
        content = _json.load(fh)
    nodes = content.get('nodes', {})
    assert any(n.startswith('email:alice') for n in nodes.keys())
    assert any(n.startswith('user:alice') for n in nodes.keys())
import os
import tempfile
import time

from src.graph.hopgraph import HopGraph


def test_persistence_roundtrip_sqlite(tmp_path):
    db = tmp_path / "hopgraph.db"
    os.environ["HOPGRAPH_PERSISTENCE_ENABLED"] = "1"
    os.environ["HOPGRAPH_DB_PATH"] = str(db)
    os.environ.pop("HOPGRAPH_EDGE_TTL_SECONDS", None)
    os.environ.pop("HOPGRAPH_PRUNE_INTERVAL_SECONDS", None)

    hg = HopGraph(wal_path=str(tmp_path/"wal.log"), snapshot_path=str(tmp_path/"snap.json"))
    now = time.time()
    hg.add_edge("host:a","process:p1","runs", ts=now)
    hg.add_edge("process:p1","ip:1.2.3.4","connects_to", ts=now)

    # New instance should preload from DB
    hg2 = HopGraph(wal_path=str(tmp_path/"wal2.log"), snapshot_path=str(tmp_path/"snap2.json"))
    assert "host:a" in hg2.adj or "host:a" in hg2.nodes
    assert any(e[0] == "ip:1.2.3.4" for e in hg2.adj.get("process:p1", []))

