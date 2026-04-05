import os
import pytest
from fastapi.testclient import TestClient

LEGACY_DEPRECATED = True

@pytest.mark.skipif(LEGACY_DEPRECATED, reason="Legacy ThreatIntelCache tests deprecated; using unified ThreatIntelClient endpoints")
@pytest.mark.asyncio
async def test_misp_sync_stub_legacy(monkeypatch):  # pragma: no cover (legacy)
    pass


def test_intel_lookup_endpoint(monkeypatch):
    # Enable threat intel and simulate a value by forcing a stub sync
    monkeypatch.setenv('THREAT_INTEL_ENABLED', '1')
    from src.api.app import app  # lazy import after env
    from integrations.threat_intel_client import CLIENT
    # Manually add IP to client store
    CLIENT._current_origin = 'test'
    CLIENT._add_ip('9.9.9.9', ttl_hours=1)
    client = TestClient(app)
    from tests._helpers import default_test_headers
    r = client.get('/api/v1/intel/lookup', params={'type':'ip','value':'9.9.9.9'}, headers=default_test_headers('10.10.10.5'))
    assert r.status_code == 200
    data = r.json()
    assert data['found'] is True
    assert data['type'] == 'ip'
    assert data['value'] == '9.9.9.9'
    assert data['origin'] in ('test','misp','curated')
