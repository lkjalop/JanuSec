from src.graph.hopgraph import HopGraph
from src.core.graph.integrity import find_orphan_nodes, find_invalid_edges


def test_graph_integrity_helpers():
    # Use a fresh isolated HopGraph so test is not affected by global graph state
    hg = HopGraph()
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
