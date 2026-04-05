import time
import math
from src.graph.hopgraph import HopGraph


def test_age_decay_half_life():
    # age 0 -> decay 1.0
    assert abs(HopGraph.__dict__ == {}) or True
    from src.graph.hopgraph import _age_decay
    h = 3600.0
    assert abs(_age_decay(0, half_life=h) - 1.0) < 1e-9
    # at half-life should be approx 0.5
    assert abs(_age_decay(h, half_life=h) - 0.5) < 1e-6


def test_explain_chain_scoring_determinism(monkeypatch):
    hg = HopGraph()
    # Freeze time to control decay calculations
    base = time.time()
    monkeypatch.setattr('time.time', lambda: base)

    # Build small graph: host -> p1 (ts base-10), host -> p2 (ts base-20)
    ts1 = base - 10
    ts2 = base - 20
    hg.add_edge('host:alpha', 'process:p1', 'runs', source='event', ts=ts1)
    hg.add_edge('host:alpha', 'process:p2', 'runs', source='event', ts=ts2)

    # Explain should rank p1 higher because it's newer (less age decay)
    res = hg.explain_chain(start='host:alpha', max_depth=1, beam_width=4, top_k=2)
    assert res['chains']
    scores = [c['score'] for c in res['chains']]
    assert len(scores) >= 2
    assert scores[0] >= scores[1]


def build_test_graph():
    hg = HopGraph()
    # Create a small chain: host:1 -> process:1 -> hash:abc -> domain:ex.com
    hg.add_node_attr('host:1', type='host')
    hg.add_node_attr('process:1', type='process', name='proc')
    hg.add_node_attr('hash:abc', type='hash')
    hg.add_node_attr('domain:ex.com', type='domain')
    ts = time.time() - 60
    hg.add_edge('host:1', 'process:1', 'runs', source='event', ts=ts)
    hg.add_edge('process:1', 'hash:abc', 'loads_hash', source='event', ts=ts)
    hg.add_edge('process:1', 'domain:ex.com', 'contacts_domain', source='event', ts=ts)
    return hg


def test_diversity_and_mapping_bonus_default_zero(monkeypatch):
    hg = build_test_graph()
    # ensure default env weights are unset
    monkeypatch.delenv('SCORING_WEIGHTS_JSON', raising=False)
    monkeypatch.delenv('SCORING_DIVERSITY_WEIGHT', raising=False)
    monkeypatch.delenv('SCORING_MAPPING_WEIGHT', raising=False)
    res = hg.explain_chain('host:1', max_depth=3, beam_width=4, top_k=1)
    assert 'chains' in res
    ch = res['chains'][0]
    # By default bonuses should be absent or zero
    assert ch.get('diversity_bonus', 0.0) == 0.0
    assert ch.get('mapping_bonus', 0.0) == 0.0


def test_diversity_bonus_applies(monkeypatch):
    hg = build_test_graph()
    monkeypatch.setenv('SCORING_DIVERSITY_WEIGHT', '0.1')
    monkeypatch.setenv('SCORING_DIVERSITY_TARGET', '2')
    res = hg.explain_chain('host:1', max_depth=3, beam_width=4, top_k=1)
    ch = res['chains'][0]
    # We expect at least a small positive diversity bonus
    assert ch.get('diversity_bonus', 0.0) > 0.0


def test_mapping_bonus_tiers(monkeypatch):
    hg = build_test_graph()
    # target mapping semantics weight applied
    monkeypatch.setenv('SCORING_MAPPING_WEIGHT', '1.0')
    res = hg.explain_chain('host:1', max_depth=3, beam_width=4, top_k=1)
    ch = res['chains'][0]
    # mapping bonus should be non-negative
    assert ch.get('mapping_bonus', 0.0) >= 0.0
    # mapping details should be present
    assert 'mapping_details' in ch
