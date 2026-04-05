from graph.hopgraph import HopGraph
import time

def test_hopgraph_explain_chain_basic():
    hg = HopGraph(wal_path='data/test_hg_wal2.log', snapshot_path='data/test_hg_snapshot2.json')
    now = time.time()
    # Create a small branching structure with different timestamps (older edges should decay)
    hg.add_edge('host:a','process:p1','runs', ts=now-10, source='sensor')  # mild decay
    hg.add_edge('process:p1','ip:1.1.1.1','connects_to', ts=now-30, source='event')  # higher decay
    hg.add_edge('process:p1','domain:evil.test','contacts_domain', ts=now-2, source='intel_feed')  # fresh & higher weight
    hg.add_edge('domain:evil.test','ip:9.9.9.9','dns_a', ts=now-1, source='intel_feed')

    expl = hg.explain_chain('host:a', max_depth=4, beam_width=5, top_k=2)
    assert expl['start'] == 'host:a'
    assert len(expl['chains']) >= 1
    # Top chain should include the higher-weight intel_feed path toward domain:evil.test
    top_chain = expl['chains'][0]
    hop_etypes = [h['etype'] for h in top_chain['hops']]
    assert 'contacts_domain' in hop_etypes
    # Score should be > 0 due to contributions
    assert top_chain['score'] > 0
