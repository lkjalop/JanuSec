from graph.hopgraph import HopGraph

def test_hopgraph_ingest_event_mapping_basic():
    hg = HopGraph(wal_path='data/test_hg_wal_ingest.log', snapshot_path='data/test_hg_snapshot_ingest.json')
    evt = {
        'timestamp': 1234567890,
        'src_host': 'HOST1',
        'process_name': 'python.exe',
        'pid': 4242,
        'src_ip': '10.0.0.5',
        'dst_ip': '1.2.3.4',
        'domain': 'example.org',
        'file_hash': 'abcd1234',
        'ja3': 'JA3ABC',
        'cert_fp': 'CERTXYZ'
    }
    hg.ingest_event(evt, source='sensor')
    # Expect a few key nodes
    assert 'host:host1' in hg.nodes
    # Process node uses process_name + pid
    assert any(n.startswith('process:python.exe') for n in hg.nodes)
    # Domain node
    assert 'domain:example.org' in hg.nodes
    # Check at least one expected edge type
    edge_types = {e[1] for edges in hg.adj.values() for e in edges}
    assert 'connects_to' in edge_types or 'contacts_domain' in edge_types
