from __future__ import annotations

import os
from fastapi.testclient import TestClient


def _client():
    os.environ['PLATFORM_LITE_INIT'] = '1'
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    from src.api.app import app
    return TestClient(app)


def test_decisions_recent_excludes_other_tenant():
    client = _client()
    # Ingest an event under tenant A
    payload = {
        'id': 'evt-bola-a',
        'details': {'process': {'name': 'notepad.exe'}}
    }
    r = client.post('/api/v1/events', json=payload, headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'tenant-A'})
    assert r.status_code == 200, r.text
    # Query recent decisions as tenant B — should not include the event
    r2 = client.get('/api/v1/decisions/recent?limit=50', headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'tenant-B'})
    assert r2.status_code == 200, r2.text
    data = r2.json()
    body = str(data)
    assert 'evt-bola-a' not in body


def test_decision_explain_wrong_tenant_denied():
    client = _client()
    # Create event for tenant A
    ev = {
        'id': 'evt-bola-explain',
        'details': {'process': {'name': 'cmd.exe'}}
    }
    r = client.post('/api/v1/events', json=ev, headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'tenant-A'})
    assert r.status_code == 200, r.text
    # Try to explain as tenant B
    r2 = client.get(f"/api/v1/decisions/{ev['id']}/explain", headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'tenant-B'})
    assert r2.status_code in (403, 404)


def test_incidents_list_excludes_other_tenant():
    client = _client()
    # Create incident under tenant A
    inc = {
        'artifact_id': 'a-1',
        'title': 'T1',
        'severity': 'high',
        'tenant_id': 'tenant-A',
        'attack_subgraph': {'nodes': [], 'edges': []}
    }
    r = client.post('/api/v1/incidents', json=inc, headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'tenant-A'})
    assert r.status_code == 200, r.text
    inc_id = r.json()['incident']['id']
    # List as tenant B and ensure it's not visible
    r2 = client.get('/api/v1/incidents', params={'limit': '50'}, headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'tenant-B'})
    assert r2.status_code == 200
    body = str(r2.json())
    assert inc_id not in body


def test_incident_subgraph_wrong_tenant_404():
    client = _client()
    inc = {
        'artifact_id': 'a-2',
        'title': 'T2',
        'severity': 'high',
        'tenant_id': 'tenant-A',
        'attack_subgraph': {'nodes': [{'id': 'n1'}], 'edges': []}
    }
    r = client.post('/api/v1/incidents', json=inc, headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'tenant-A'})
    assert r.status_code == 200
    inc_id = r.json()['incident']['id']
    r2 = client.get(f'/api/v1/incidents/{inc_id}/attack_subgraph', headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'tenant-B'})
    assert r2.status_code in (403, 404)


def test_decision_explain_missing_tenant_allowed():
    client = _client()
    ev = {
        'id': 'evt-no-tenant-hdr',
        'details': {'process': {'name': 'cmd.exe'}}
    }
    r = client.post('/api/v1/events', json=ev, headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'tenant-A'})
    assert r.status_code == 200
    r2 = client.get(f"/api/v1/decisions/{ev['id']}/explain", headers={'x-api-key': 'devkey123'})
    assert r2.status_code == 200
