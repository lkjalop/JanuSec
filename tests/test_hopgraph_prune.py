import time
from graph.hopgraph import HopGraph

def test_hopgraph_prune_ttl():
    hg = HopGraph(wal_path='data/test_hg_wal_prune.log', snapshot_path='data/test_hg_snapshot_prune.json')
    hg.edge_ttl_seconds = 5
    now = time.time()
    hg.add_edge('host:a','ip:1.1.1.1','conn', ts=now-10)  # should be pruned
    hg.add_edge('host:a','ip:2.2.2.2','conn', ts=now-2)   # should remain
    hg.prune(now=now)
    # Only recent edge should remain
    remaining_edges = [(src, e) for src, lst in hg.adj.items() for e in lst]
    assert any(e[0]=='ip:2.2.2.2' for _src, (e) in remaining_edges)
    assert not any(e[0]=='ip:1.1.1.1' for _src, (e) in remaining_edges)
