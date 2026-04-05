import os
import tempfile
import json
import time
from src.graph.hopgraph import HopGraph
from src.core.graph.persistence.sqlite_backend import SQLiteHopGraphBackend


def test_snapshot_wal_roundtrip(tmp_path):
    dbp = str(tmp_path / 'hg.db')
    wal = str(tmp_path / 'hg_wal.log')
    snap = str(tmp_path / 'hg_snap.json')
    # start graph with DB backend enabled
    backend = SQLiteHopGraphBackend(dbp)
    g = HopGraph(wal_path=wal, snapshot_path=snap)
    g.backend = backend
    # create some nodes/edges
    g.add_node_attr('n:one', type='host')
    g.add_node_attr('n:two', type='process')
    g.add_edge('n:one', 'n:two', 'runs', source='event', ts=time.time())
    g.add_edge('n:two', 'n:three', 'loads_hash', source='intel_feed', ts=time.time())
    # save snapshot (writes meta to DB)
    g.save_snapshot()
    # add more WAL entries
    g.add_edge('n:three', 'n:four', 'contacts_domain', source='event', ts=time.time())
    g.add_node_attr('n:four', type='domain')
    # capture counts from original graph
    orig_nodes = set(g.nodes.keys())
    orig_edges = sum(len(v) for v in g.adj.values())
    # create fresh graph instance and load snapshot
    g2 = HopGraph(wal_path=wal, snapshot_path=snap)
    g2.backend = backend
    # reset in-memory seq counter to ensure we don't reuse in test harness
    g2._seq_counter = g._seq_counter
    g2.load_snapshot()
    # assert restored state matches original
    restored_nodes = set(g2.nodes.keys())
    restored_edges = sum(len(v) for v in g2.adj.values())
    assert orig_nodes == restored_nodes
    assert orig_edges == restored_edges


def test_deterministic_wal_ordering(tmp_path, monkeypatch):
    dbp = str(tmp_path / 'hg2.db')
    backend = SQLiteHopGraphBackend(dbp)
    wal = str(tmp_path / 'hg2_wal.log')
    snap = str(tmp_path / 'hg2_snap.json')
    g = HopGraph(wal_path=wal, snapshot_path=snap)
    g.backend = backend
    # create a snapshot baseline
    g.add_node_attr('a:1', type='host')
    g.save_snapshot()
    # Inject WAL records out-of-order into DB directly
    # simulate seq 10,12,11 order insertion
    backend.save_wal_record(10, 'edge', {'op':'edge','src':'a:1','dst':'b:1','etype':'runs','srcv':'event','ts':time.time(),'attrs':{},'w':1.0,'seq':10})
    backend.save_wal_record(12, 'edge', {'op':'edge','src':'b:1','dst':'c:1','etype':'loads_hash','srcv':'intel_feed','ts':time.time(),'attrs':{},'w':1.0,'seq':12})
    backend.save_wal_record(11, 'edge', {'op':'edge','src':'a:1','dst':'c:1','etype':'connects_to','srcv':'event','ts':time.time(),'attrs':{},'w':1.0,'seq':11})
    # enable deterministic ordering
    monkeypatch.setenv('HOPGRAPH_DETERMINISTIC','1')
    # new instance to load
    g2 = HopGraph(wal_path=wal, snapshot_path=snap)
    g2.backend = backend
    g2.load_snapshot()
    # ensure edges are present and consistent
    edges = []
    for src, lst in g2.adj.items():
        for e in lst:
            edges.append((src, e[0], e[1]))
    # Expect three edges with the given relationships
    assert ('a:1','b:1','runs') in edges
    assert ('b:1','c:1','loads_hash') in edges
    assert ('a:1','c:1','connects_to') in edges