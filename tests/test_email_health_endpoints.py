import os
import pytest
from fastapi.testclient import TestClient

from src.api.server import app

@pytest.fixture(autouse=True)
def allow_dev_api_key(monkeypatch):
    monkeypatch.setenv('ALLOW_DEV_API_KEY', '1')

def test_proofpoint_health_endpoint():
    client = TestClient(app)
    r = client.get('/api/v1/email/connectors/proofpoint/health?tenant_id=default')
    assert r.status_code in (200, 503)  # Collector may be unavailable in test mode
    if r.status_code == 200:
        js = r.json()
        assert 'tenant' in js

def test_mimecast_health_endpoint():
    client = TestClient(app)
    r = client.get('/api/v1/email/connectors/mimecast/health?tenant_id=default')
    assert r.status_code in (200, 503)
    if r.status_code == 200:
        js = r.json()
        assert 'tenant' in js

def test_arc_bimi_enforce_endpoint():
    client = TestClient(app)
    payload = {
        'headers': 'Authentication-Results: example.net; dmarc=fail arc=fail'
    }
    r = client.post('/api/v1/email/security/arc_bimi/enforce', json=payload)
    assert r.status_code == 200
    js = r.json()
    assert js['enforcement'] in ('none','quarantine')
