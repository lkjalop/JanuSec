import asyncio
import hashlib
import json
import os
import time

import pytest
from httpx import AsyncClient

from src.api.alerts_endpoints import get_tenant_alert_path
from src.api.server import app


@pytest.mark.asyncio
async def test_tenant_header_required_when_disabled(monkeypatch):
    # Force no default tenant fallback
    monkeypatch.setenv('ALLOW_DEFAULT_TENANT','0')
    async with AsyncClient(app=app, base_url='http://test') as client:
        # Missing tenant
        r = await client.post('/api/v1/events', json={'id':'t-no-tenant','details':{'process':{'name':'notepad.exe'}}})
        assert r.status_code in (400,422)  # dependency rejects
        # With tenant header should succeed
        r2 = await client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantTest'}, json={'id':'t-with-tenant','details':{'process':{'name':'notepad.exe'}}})
        assert r2.status_code == 200
        data = r2.json()
        assert data['event_id'] == 't-with-tenant'

@pytest.mark.asyncio
async def test_alert_search_tenant_isolation(monkeypatch, tmp_path):
    # Use temp artifacts directory
    monkeypatch.setenv('ALERTS_LOG_PATH', str(tmp_path / 'alerts.jsonl'))
    # Ensure default tenant fallback ON for speed
    monkeypatch.setenv('ALLOW_DEFAULT_TENANT','1')
    async with AsyncClient(app=app, base_url='http://test') as client:
        # Create alert via direct ingest for tenantA
        await client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantA'}, json={'id':'a1','details':{'process':{'name':'powershell.exe'}}})
        await client.post('/api/v1/events', headers={'X-Tenant-Id':'tenantB'}, json={'id':'b1','details':{'process':{'name':'powershell.exe'}}})
        # Recent filtered
        rA = await client.get('/api/v1/alerts/recent?tenant_id=tenantA')
        rB = await client.get('/api/v1/alerts/recent?tenant_id=tenantB')
        assert rA.status_code == 200 and rB.status_code == 200
        a_alerts = rA.json()['alerts']; b_alerts = rB.json()['alerts']
        assert all(a.get('tenant_id')=='tenantA' for a in a_alerts)
        assert all(b.get('tenant_id')=='tenantB' for b in b_alerts)
        # Mixed call (no tenant) should include both tenants (at least 2 total)
        rAll = await client.get('/api/v1/alerts/recent')
        assert rAll.status_code == 200
        all_alerts = rAll.json()['alerts']
        assert any(a.get('tenant_id')=='tenantA' for a in all_alerts)
        assert any(a.get('tenant_id')=='tenantB' for a in all_alerts)

@pytest.mark.asyncio
async def test_hash_chain_continuity_per_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv('ALERTS_LOG_PATH', str(tmp_path / 'alerts.jsonl'))
    monkeypatch.setenv('ALLOW_DEFAULT_TENANT','1')
    t = 'tenantChain'
    path = get_tenant_alert_path(t)
    async with AsyncClient(app=app, base_url='http://test') as client:
        await client.post('/api/v1/events', headers={'X-Tenant-Id':t}, json={'id':'c1','details':{'process':{'name':'powershell.exe'}}})
        await client.post('/api/v1/events', headers={'X-Tenant-Id':t}, json={'id':'c2','details':{'process':{'name':'powershell.exe'}}})
    # Read file and validate prev_hash->hash linkage
    assert os.path.exists(path)
    hashes = []
    with open(path,encoding='utf-8') as f:
        prev = None
        for line in f:
            line=line.strip()
            if not line: continue
            rec = json.loads(line)
            assert rec.get('prev_hash') == prev
            h = rec.get('hash'); assert h
            prev = h
            hashes.append(h)
    assert len(hashes) >= 2
