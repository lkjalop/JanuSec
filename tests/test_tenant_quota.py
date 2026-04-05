import os, json
os.environ['PLATFORM_LITE_INIT'] = '1'
from fastapi.testclient import TestClient
from src.api.app import app


def test_tenant_quota_get_update():
    client = TestClient(app)
    os.environ['API_KEYS_JSON'] = json.dumps([{'key':'testkey123','scopes':['*']}])
    tid = 'test-tenant'
    # Get default
    r = client.get(f'/api/v1/tenants/{tid}/quota', headers={'X-API-Key': 'testkey123'})
    assert r.status_code == 200
    body = r.json()
    assert 'max_pulls' in body and 'window_seconds' in body

    # Update
    r2 = client.post(f'/api/v1/tenants/{tid}/quota', json={'max_pulls': 5, 'window_seconds': 600}, headers={'X-API-Key': 'testkey123'})
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2['max_pulls'] == 5
    assert b2['window_seconds'] == 600
