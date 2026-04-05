from src.api.server import DECISION_CACHE, explain_decision


def test_explain_includes_hopgraph_and_recommendations():
    event_id = 'evt-hopgraph'
    DECISION_CACHE[event_id] = {
        'event_id': event_id,
        'factors': ['endpoint:vss_deletion'],
        'verdict': 'SUSPICIOUS',
        'confidence': 0.7,
        'hopgraph_context': {'chains': [{'nodes': ['user:alice', 'host:web01']}]},
        'ttl_seconds': 120,
        'expires_at': 9999999999,
        'recommendation_catalog': [{'domain': 'identity', 'action': 'reset password', 'priority': 'high'}],
        'recommendation_actions': [{'id': 'identity.reset', 'action': 'reset password', 'status': 'pending'}],
        'dependency_status': {'hopgraph': {'available': True}},
        'factor_synthesis': {'final_score': 0.8, 'confidence': 0.82, 'contributing_factors': [], 'synergies': []},
    }
    resp = explain_decision(event_id)
    assert resp['hopgraph_context']['chains'][0]['nodes'][0] == 'user:alice'
    assert resp['ttl_seconds'] == 120
    assert resp['recommendation_catalog'][0]['action'] == 'reset password'
    assert resp['factor_synthesis']['final_score'] == 0.8
