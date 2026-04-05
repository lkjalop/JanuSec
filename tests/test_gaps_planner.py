import os
import json
# Force lite init to avoid heavy import paths during tests
os.environ['PLATFORM_LITE_INIT'] = '1'
from fastapi.testclient import TestClient

from src.api.app import app


def test_incident_asks_confidence_gate():
    client = TestClient(app)
    # set permissive test API key in env for auth_dependency
    os.environ['API_KEYS_JSON'] = json.dumps([{'key':'testkey123','scopes':['*']}])
    payload = {'incident': {'confidence': 0.95, 'entities': {}}}
    res = client.post('/api/v1/gaps/incident/asks', json=payload, headers={'X-API-Key': 'testkey123'})
    assert res.status_code == 200
    body = res.json()
    assert 'asks' in body
    assert body['asks'] == []


def test_incident_asks_returns_asks_low_confidence():
    client = TestClient(app)
    os.environ['API_KEYS_JSON'] = json.dumps([{'key':'testkey123','scopes':['*']}])
    payload = {'incident': {'confidence': 0.1, 'entities': {'users': ['alice'], 'hosts': ['host1']}, 'time_window_minutes': 30}}
    res = client.post('/api/v1/gaps/incident/asks', json=payload, headers={'X-API-Key': 'testkey123'})
    assert res.status_code == 200
    body = res.json()
    assert 'asks' in body
    assert len(body['asks']) >= 1
    # each ask should have api.endpoint
    assert any('api' in a and 'endpoint' in a['api'] for a in body['asks'])
