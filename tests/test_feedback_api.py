import json
import time
from fastapi.testclient import TestClient

from src.api.app import app  # reuse existing FastAPI instance

client = TestClient(app)

def _seed_decision(event_id: str, factors: list[str]):
    # Minimal injection into DECISION_CACHE to simulate a prior decision
    from src.api import runtime_state
    runtime_state.cache_set(event_id, {
        'event_id': event_id,
        'verdict': 'SUSPICIOUS',
        'confidence': 0.73,
        'decision_type': 'auto',
        'factors': list(factors),
        'ts': time.time(),
    })

def test_feedback_submit_and_get():
    eid = 'evt-feedback-1'
    _seed_decision(eid, ['factor:one','factor:two'])
    r = client.post('/api/v1/feedback', json={'event_id': eid, 'verdict': 'tp'})
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload['record']['event_id'] == eid
    assert payload['record']['classification'] == 'tp'
    # factors snapshot present
    assert len(payload['record']['factors']) == 2
    # fetch
    g = client.get(f'/api/v1/feedback/{eid}')
    assert g.status_code == 200
    got = g.json()
    assert got['classification'] == 'tp'
    assert len(got['factors']) == 2

def test_feedback_upsert_overwrites_and_stats():
    eid = 'evt-feedback-2'
    _seed_decision(eid, ['alpha','beta','gamma'])
    r1 = client.post('/api/v1/feedback', json={'event_id': eid, 'verdict': 'fp'})
    assert r1.status_code == 200
    r2 = client.post('/api/v1/feedback', json={'event_id': eid, 'verdict': 'tp'})  # overwrite classification
    assert r2.status_code == 200
    g = client.get('/api/v1/feedback/stats')
    assert g.status_code == 200
    stats = g.json()
    assert stats['by_classification'].get('tp') >= 1
    # quality listing
    q = client.get('/api/v1/feedback/factors?limit=50&sort=asc')
    assert q.status_code == 200
    qpayload = q.json()
    assert 'factors' in qpayload
    # ensure factor entries include score
    if qpayload['factors']:
        assert 'score' in qpayload['factors'][0]
