from src.core.graph import network_hopgraph


def test_ingest_bgp_prefix_adds_bgp_meta_and_routing_edge():
    prefix = '203.0.113.0/24'
    # ensure a clean state for the node
    node = f"route:{prefix}"
    if node in network_hopgraph.GLOBAL_NETWORK_GRAPH._adj:
        del network_hopgraph.GLOBAL_NETWORK_GRAPH._adj[node]

    network_hopgraph.ingest_bgp_prefix(prefix, {'source': 'unittest', 'note': 'meta-test'})

    adj = network_hopgraph.GLOBAL_NETWORK_GRAPH._adj.get(node, [])
    # expect a routing edge to internet root
    assert any(dst == 'route:0.0.0.0/0' for (dst, _t, _ts, _w) in adj)
    # expect a bgp_meta self-edge (meta stored as self-edge with type 'bgp_meta')
    assert any(dst == node and (_t == 'bgp_meta' or _t == 'bgp_meta') for (dst, _t, _ts, _w) in adj)
