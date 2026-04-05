from src.graph.hopgraph import GLOBAL_HOPGRAPH
from src.core.graph.integrity import find_orphan_nodes, find_invalid_edges


def test_graph_integrity_helpers():
    # Setup minimal graph
    GLOBAL_HOPGRAPH.add_node_attr('host:A', type='host', name='A')
    GLOBAL_HOPGRAPH.add_node_attr('process:P', type='process', name='P')
    GLOBAL_HOPGRAPH.add_edge('host:A', 'process:P', 'runs')

    orphans = find_orphan_nodes(GLOBAL_HOPGRAPH)
    assert 'host:A' not in orphans
    assert 'process:P' not in orphans
    invalid = find_invalid_edges(GLOBAL_HOPGRAPH)
    assert not invalid

    # Add an orphan
    GLOBAL_HOPGRAPH.add_node_attr('domain:orphan.example', type='domain', name='orphan.example')
    orphans2 = find_orphan_nodes(GLOBAL_HOPGRAPH)
    assert 'domain:orphan.example' in orphans2
