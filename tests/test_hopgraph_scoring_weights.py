import os
import pytest

@pytest.fixture(autouse=True)
def setup_env():
    # Apply non-zero weights to observe bonuses in explain_chain
    os.environ['SCORING_WEIGHTS_JSON'] = '{"mapping":0.5,"diversity":0.5}'
    yield


def test_explain_chain_applies_mapping_and_diversity_bonuses():
    from src.graph.hopgraph import HopGraph
    hg = HopGraph()
    # Build a path with diverse node types and high-value mapping fields
    # host -> process -> loads_hash -> contacts_domain
    host = 'host:alpha'
    proc = 'process:app:1234'
    hsh = 'hash:deadbeef'
    dom = 'domain:example.com'
    hg.add_node_attr(host, type='host')
    hg.add_node_attr(proc, type='process')
    hg.add_node_attr(hsh, type='hash')
    hg.add_node_attr(dom, type='domain')
    hg.add_edge(host, proc, 'runs', source='event')
    hg.add_edge(proc, hsh, 'loads_hash', source='event')
    hg.add_edge(proc, dom, 'contacts_domain', source='event')
    out = hg.explain_chain(start=host, max_depth=4, beam_width=5, top_k=1)
    chains = out.get('chains') or []
    assert chains, 'expected at least one chain'
    ch = chains[0]
    # Bonuses present and positive
    assert ch.get('diversity_bonus', 0.0) > 0.0
    assert ch.get('mapping_bonus', 0.0) > 0.0
    # Diversity details reflect distinct types >= 3
    dd = ch.get('diversity_details') or {}
    assert (dd.get('distinct') or 0) >= 3
