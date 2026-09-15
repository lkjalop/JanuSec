from fastapi.testclient import TestClient
import os
from src.api.app import create_app


def test_admin_init_db_and_ab_endpoints():
    app = create_app({'testing': True})
    client = TestClient(app)

    # Ensure permissive test API key is accepted by auth.require_scopes in pytest
    headers = {'x-api-key': 'testkey123'}

    # init db
    r = client.post('/api/v1/metrics/admin/init_db', headers=headers)
    assert r.status_code == 200
    assert r.json().get('status') == 'ok'

    # record an AB result
    payload = {'ab_test_id': 'test-1', 'variant': 'A', 'label': 'tp', 'event_id': 'evt-1', 'reviewer': 'analyst1'}
    r = client.post('/api/v1/metrics/ab_tests/record', json=payload, headers=headers)
    assert r.status_code == 200

    # fetch summary
    r = client.get('/api/v1/metrics/ab_tests/test-1/summary', headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data.get('ab_test_id') == 'test-1'
    assert 'A' in data.get('summary', {})
