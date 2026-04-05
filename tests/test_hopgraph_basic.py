from graph.hopgraph import HopGraph

def test_hopgraph_add_and_query():
    hg = HopGraph(wal_path='data/test_hg_wal.log', snapshot_path='data/test_hg_snapshot.json')
    hg.add_edge('host:A','ip:1.2.3.4','conn','sensor')
    hg.add_edge('ip:1.2.3.4','domain:evil.test','dns','sensor')
    res = hg.k_hops('host:A', k=2)
    assert res['start']=='host:A'
    assert len(res['nodes']) >= 3
    etypes = {e['etype'] for e in res['edges']}
    assert 'conn' in etypes and 'dns' in etypes

def test_snapshot_roundtrip(tmp_path):
    wal = tmp_path / 'wal.log'
    snap = tmp_path / 'snap.json'
    hg = HopGraph(wal_path=str(wal), snapshot_path=str(snap))
    hg.add_edge('host:A','ip:1.1.1.1','conn')
    hg.save_snapshot()
    # New instance reload
    hg2 = HopGraph(wal_path=str(wal), snapshot_path=str(snap))
    hg2.load_snapshot()
    res = hg2.k_hops('host:A', k=1)
    assert 'ip:1.1.1.1' in res['nodes']
