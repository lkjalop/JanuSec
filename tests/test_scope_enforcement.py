import os
from fastapi.testclient import TestClient


def setup_module(module):
    # Minimal env: admin token and API keys
    os.environ['ADMIN_UI_TOKEN'] = 'admin-test'
    os.environ['API_KEYS_JSON'] = '[{"key":"key-no-scope","scopes":[]},{"key":"key-feedback","scopes":["feedback.write"]}]'


def get_client():
    from src.api.app import create_app
    app = create_app({'mode': 'test'})
    return TestClient(app)


def test_promote_requires_admin():
    client = get_client()
    files = {'file': ('m.json', '{"type":"sigmoid","k":1.0,"x0":0.0}', 'application/json')}
    # No admin token -> 401
    r = client.post('/api/v1/models/promote', files=files)
    assert r.status_code == 401
    # With admin token -> 200
    r2 = client.post('/api/v1/models/promote', headers={'Authorization':'Bearer admin-test'}, files=files)
    assert r2.status_code == 200


def test_alias_requires_admin():
    client = get_client()
    # No admin token -> 401
    r = client.post('/api/v1/models/alias', json={'alias':'current','model_name':'m.json'})
    assert r.status_code == 401
    # With admin token -> 200
    r2 = client.post('/api/v1/models/alias', headers={'Authorization':'Bearer admin-test'}, json={'alias':'current','model_name':'m.json'})
    assert r2.status_code == 200


def test_label_requires_feedback_scope():
    client = get_client()
    # Ensure a decision exists to label
    from src.api.server import DECISION_CACHE
    from src.api import runtime_state as _rs
    _rs.cache_set('evt-x', {'event_id':'evt-x','verdict':'OBSERVE','confidence':0.1,'factors':[]})
    # No auth -> 401
    r = client.post('/api/v1/decisions/evt-x/label', json={'label':'tp'})
    assert r.status_code == 401
    # API key with no scopes -> 403
    r2 = client.post('/api/v1/decisions/evt-x/label', headers={'x-api-key':'key-no-scope'}, json={'label':'tp'})
    assert r2.status_code == 403
    # API key with feedback.write -> 200
    r3 = client.post('/api/v1/decisions/evt-x/label', headers={'x-api-key':'key-feedback'}, json={'label':'tp'})
    assert r3.status_code == 200


def test_calibration_accept_requires_scope():
    client = get_client()
    # No auth -> 401
    r = client.post('/api/v1/risk/calibration/proposals/12345.0/accept')
    assert r.status_code == 401


def test_dlq_list_requires_admin():
    client = get_client()
    r = client.get('/api/v1/dlq')
    assert r.status_code == 401
    r2 = client.get('/api/v1/dlq', headers={'Authorization':'Bearer admin-test'})
    # Backend DB not necessarily configured; allow 200 or 500 here, but not 401
    assert r2.status_code in (200, 500)
