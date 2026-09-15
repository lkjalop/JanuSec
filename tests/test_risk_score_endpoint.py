import math
from fastapi.testclient import TestClient

from src.api.server import app, DECISION_CACHE, _record_decision  # type: ignore

client = TestClient(app)

def test_risk_score_post_basic():
    decision = {
        'event_id': 'risk-post-1',
        'factors': ['scenario:critical_exec','net:suspicious_domain','endpoint:signed_mismatch'],
        'confidence': 0.9
    }
    r = client.post('/api/v1/risk/score', json={'decision': decision})
    assert r.status_code == 200
    data = r.json()
    for key in ('score','raw_score','breakdown','method'):
        assert key in data
    assert 0.0 <= data['score'] <= 1.0
    assert data['method'] == 'multiplicative'
    assert any(b['factor'] == 'scenario:critical_exec' for b in data['breakdown'])

def test_risk_score_get_via_cache():
    evt_id = 'risk-cache-1'
    from src.api import runtime_state
    runtime_state.cache_set(evt_id, {'event_id': evt_id, 'factors': ['net:a','dns:b','endpoint:x'], 'confidence': 1.0})
    r = client.get(f'/api/v1/risk/score/{evt_id}')
    assert r.status_code == 200
    data = r.json()
    assert 0.0 <= data['score'] <= 1.0
    assert data['method'] == 'multiplicative'

def test_risk_score_post_empty():
    decision = {'event_id': 'risk-empty', 'factors': [], 'confidence': 0.4}
    r = client.post('/api/v1/risk/score', json={'decision': decision})
    assert r.status_code == 200
    data = r.json()
    # With no positive contributions score should be near 0
    assert data['score'] <= 0.05

def test_risk_score_post_extreme_negative_values():
    # Provide factors plus simulate penalty via low coverage; ensure clamped
    decision = {
        'event_id': 'risk-extreme',
        'factors': ['net:a'],
        'confidence': 0.2
    }
    r = client.post('/api/v1/risk/score', json={'decision': decision})
    assert r.status_code == 200
    data = r.json()
    assert data['score'] >= 0.0
    assert data['score'] <= 1.0
    assert not math.isnan(data['score'])
