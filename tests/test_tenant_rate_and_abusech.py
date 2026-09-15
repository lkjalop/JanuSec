import asyncio
import json
import os
import time

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
app = create_app({'mode': 'test'})
from src.integrations.threat_intel_client import ThreatIntelClient


def _admin_headers():
    os.environ['ADMIN_API_KEY'] = 'adminkey'
    return {'X-Admin-Key': 'adminkey'}


def test_admin_rate_limits_view_and_set():
    client = TestClient(app)
    # View defaults
    r = client.get('/api/v1/admin/rate_limits/tenant', headers=_admin_headers())
    assert r.status_code == 200
    data = r.json()
    assert 'enabled' in data and 'max' in data and 'window_seconds' in data
    # Update values
    r2 = client.post('/api/v1/admin/rate_limits/tenant', headers=_admin_headers(), json={'enabled': True, 'max': 50, 'window_seconds': 30})
    assert r2.status_code == 200
    cfg = r2.json()
    assert cfg['max'] == 50 and cfg['window_seconds'] == 30


def test_admin_rate_limits_forbidden_without_key():
    client = TestClient(app)
    r = client.get('/api/v1/admin/rate_limits/tenant')
    assert r.status_code in (401,403)


def test_worker_bypass_header_skips_rate_limit(monkeypatch):
    # Configure a tiny rate limit window
    os.environ['TENANT_RATE_LIMIT_ENABLED'] = '1'
    os.environ['TENANT_RATE_LIMIT_MAX'] = '1'
    os.environ['TENANT_RATE_LIMIT_WINDOW'] = '60'
    os.environ['X_WORKER_SECRET'] = 'secret'
    from importlib import reload
    import src.api.app as appmod
    reload(appmod)
    client = TestClient(appmod.app)
    # First request increments
    r1 = client.get('/health', headers={'X-Tenant-ID': 't1'})
    assert r1.status_code == 200
    # Second would 429, but bypass header should skip limit
    r2 = client.get('/health', headers={'X-Tenant-ID': 't1', 'X-Worker-Secret': appmod._WORKER_BYPASS_TOKEN})
    assert r2.status_code == 200


@pytest.mark.asyncio
async def test_abusech_conditional_get_no_dup(monkeypatch):
    cli = ThreatIntelClient()
    # Simulate first fetch returns content; second returns 304 via empty string per helper logic
    results = ['ja3,desc\n769,foo\n', '']
    async def fake_get(url, headers=None, timeout=8.0, retries=2, backoff=1.5):
        return results.pop(0)
    monkeypatch.setattr(cli, '_http_get', fake_get)
    before = len(cli.ja3_set)
    await cli._sync_abusech_sslbl()
    mid = len(cli.ja3_set)
    await cli._sync_abusech_sslbl()  # 304/no-update path
    after = len(cli.ja3_set)
    assert mid == after and after >= before
