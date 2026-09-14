from src.graph.hopgraph import GLOBAL_HOPGRAPH

def test_corr_domain_pivot_sequence_emission():
    proc = 'process:pivotproc:9999'
    GLOBAL_HOPGRAPH.add_node_attr(proc, type='process', name='pivotproc')
    # Create 5 distinct domain contacts within window
    domains = ['a.example.com','b.example.com','c.example.com','d.example.com','e.example.com']
    for d in domains:
        dom_node = f'domain:{d}'
        GLOBAL_HOPGRAPH.add_node_attr(dom_node, type='domain', name=d)
        GLOBAL_HOPGRAPH.add_edge(proc, dom_node, 'contacts_domain')
    # Invoke detection explicitly (maintenance loop would do this normally)
    GLOBAL_HOPGRAPH.detect_domain_pivot_sequences(window_seconds=600, min_prefixes=5)
    factors = GLOBAL_HOPGRAPH.get_node_factors(proc)
    assert 'corr_domain_pivot_sequence' in factors
