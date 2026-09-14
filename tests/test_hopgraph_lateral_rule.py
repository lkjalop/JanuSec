from src.core.graph.hopgraph_lite import get_graph
from src.core.graph.hopgraph_integration import enrich_event_with_lateral_chain
from src.core.correlation.rules.graph.lateral_chain_burst import graph_lateral_chain_burst


def test_hopgraph_lateral_chain_rule_triggers():
    g = get_graph()
    # Simulate auth edges user->host1, host1->host2, host2->host3 as net edges
    g.edges_ts.clear()
    # Manually inject edges with current timestamps via observe events
    g.observe({'edge_type': 'auth', 'user': 'alice', 'host': 'host1'})
    g.observe({'edge_type': 'net', 'host': 'host1', 'peer': 'host2'})
    g.observe({'edge_type': 'net', 'host': 'host2', 'peer': 'host3'})
    base_event = {'user': 'alice'}
    enriched = enrich_event_with_lateral_chain(base_event)
    assert enriched.get('graph_lateral_chain_len', 0) >= 3
    # Should set rapid flag
    assert enriched.get('graph_lateral_rapid') is True
    # Rule should fire
    assert graph_lateral_chain_burst(enriched)
