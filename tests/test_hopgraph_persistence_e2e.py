from src.graph.hopgraph import HopGraph


def test_hopgraph_persistence_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv('HOPGRAPH_PERSISTENCE_ENABLED', '1')
    monkeypatch.setenv('HOPGRAPH_DB_PATH', str(tmp_path / 'hopgraph.db'))

    wal = tmp_path / 'hopgraph_wal.log'
    snap = tmp_path / 'hopgraph_snapshot.json'
    hg = HopGraph(wal_path=str(wal), snapshot_path=str(snap))
    hg.add_node_attr('user:alice', type='user', label='Alice')
    hg.add_node_attr('host:web01', type='host', label='web01')
    hg.add_edge('user:alice', 'host:web01', 'logged_in', source='event')

    hg2 = HopGraph(wal_path=str(tmp_path / 'hopgraph_wal2.log'), snapshot_path=str(tmp_path / 'hopgraph_snapshot2.json'))
    edges = hg2.adj.get('user:alice', [])
    assert any(dst == 'host:web01' and etype == 'logged_in' for dst, etype, *_ in edges)
