import time

from src.api.server import _merge_decision_meta


def test_merge_decision_meta_copies_known_fields():
    now = time.time()
    meta = {
        'hopgraph_context': {'chains': [{'score': 0.9}]},
        'recommendation_catalog': [{'id': 'identity.reset', 'action': 'Reset credentials'}],
        'recommendation_actions': [{'id': 'identity.reset', 'status': 'pending'}],
        'dependency_status': {'hopgraph': {'available': True}},
        'ttl_seconds': 300,
        'expires_at': now + 300,
        'correlation_insights': [{'type': 'multi_domain_chain', 'chain_id': 'c-1'}],
    }
    decision = {}
    _merge_decision_meta(decision, meta)
    assert decision['hopgraph_context']['chains'][0]['score'] == 0.9
    assert decision['recommendation_catalog'][0]['action'] == 'Reset credentials'
    assert decision['dependency_status']['hopgraph']['available'] is True
    assert decision['ttl_seconds'] == 300
    assert decision['correlation_insights'][0]['chain_id'] == 'c-1'


def test_merge_decision_meta_noop_on_empty_meta():
    decision = {'verdict': 'OBSERVE'}
    _merge_decision_meta(decision, None)
    assert decision == {'verdict': 'OBSERVE'}
