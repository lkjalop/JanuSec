import pytest
from src.graph.hopgraph import HopGraph
from src.core.graph.integrity import find_orphan_nodes, find_invalid_edges


def test_graph_integrity_helpers(monkeypatch, tmp_path):
    # Disable persistence + use temp paths so HopGraph() starts completely empty
    monkeypatch.setenv('HOPGRAPH_PERSISTENCE_ENABLED', '0')
    hg = HopGraph(
        wal_path=str(tmp_path / 'test_wal.log'),
        snapshot_path=str(tmp_path / 'test_snapshot.json'),
    )
    hg.add_node_attr('host:A', type='host', name='A')
    hg.add_node_attr('process:P', type='process', name='P')
    hg.add_edge('host:A', 'process:P', 'runs')

    orphans = find_orphan_nodes(hg)
    assert 'host:A' not in orphans
    assert 'process:P' not in orphans
    invalid = find_invalid_edges(hg)
    assert not invalid

    # Add an orphan
    hg.add_node_attr('domain:orphan.example', type='domain', name='orphan.example')
    orphans2 = find_orphan_nodes(hg)
    assert 'domain:orphan.example' in orphans2
