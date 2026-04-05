from src.core.graph.remote_access_hopgraph import RemoteAccessEvent, make_nodes_and_edges


def test_make_nodes_and_edges_basic():
    ev = RemoteAccessEvent(src_ip='10.0.0.5', user='alice', dest_host='vm1', dest_port=443, protocol='vpn', timestamp='ts1', raw={'foo':'bar'})
    payload = make_nodes_and_edges(ev)
    assert 'nodes' in payload and 'edges' in payload
    assert any(n['id'] == 'user:alice' for n in payload['nodes'])
    assert any(e['type'] == 'remote_access' or e.get('etype') == 'remote_access' for e in payload['edges'])
