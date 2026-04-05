import os
import pytest
from fastapi.testclient import TestClient

from src.api.server import app

@pytest.fixture(autouse=True)
def allow_dev_api_key(monkeypatch):
    monkeypatch.setenv('ALLOW_DEV_API_KEY', '1')

def test_thresholds_get_set_status(monkeypatch):
    client = TestClient(app)
    # Set threshold
    r = client.post('/api/v1/admin/ingest/thresholds', json={'items': {'default': 2}})
    assert r.status_code == 200
    # Status should include drops (may be empty) and computed alerts if drops exceed
    r2 = client.get('/api/v1/admin/ingest/status')
    assert r2.status_code == 200
    js = r2.json()
    assert 'drops' in js and 'alerts' in js
    # Reset drops
    r3 = client.post('/api/v1/admin/ingest/reset', json={'tenant_id': 'default'})
    assert r3.status_code == 200
