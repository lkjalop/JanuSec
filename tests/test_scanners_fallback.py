import os
import pytest
from fastapi.testclient import TestClient

from src.api.app import app

client = TestClient(app)

@pytest.mark.asyncio
async def test_snyk_trigger_fallback(monkeypatch):
    os.environ['ALLOW_DEV_API_KEY'] = '1'
    headers = {'x-api-key':'devkey123'}
    # Ensure real-mode disabled
    os.environ['SCANNERS_REAL_MODE'] = '0'
    from src.collectors.scanners.snyk_connector import SnykConnector
    async def fake_forward(self, payload):
        return {'ok': True}
    monkeypatch.setattr(SnykConnector, 'forward_to_sbom', fake_forward)
    r = client.post('/api/v1/scanners/snyk/trigger', json={'project':'demo'}, headers=headers)
    assert r.status_code == 200
    j = r.json()
    assert j['status'] == 'scheduled'
    assert j['target'] == 'demo'
