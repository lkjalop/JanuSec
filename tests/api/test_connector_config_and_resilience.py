import os

import pytest
from fastapi.testclient import TestClient


API_KEY = os.environ.get('TEST_API_KEY', 'devkey123')


@pytest.fixture(scope='module')
def client():
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    from src.api.app import app
    return TestClient(app)


def _headers():
    return {'x-api-key': API_KEY}


def test_azure_connector_config_roundtrip(client):
    tenant = 'cfg-tenant'
    resp = client.put(
        f'/api/v1/connectors/{tenant}/azure/entra_signin/config',
        headers=_headers(),
        json={'config': {'tenant_id': 'tenant-123', 'client_id': 'cid', 'client_secret': 'secret', 'auth_mode': 'client_secret'}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body['config']['tenant_id'] == 'tenant-123'
    assert body['config']['has_client_secret'] is True

    get_resp = client.get(f'/api/v1/connectors/{tenant}/azure/entra_signin/config', headers=_headers())
    assert get_resp.status_code == 200
    assert get_resp.json()['config']['tenant_id'] == 'tenant-123'
    assert get_resp.json()['config']['has_client_secret'] is True


def test_connector_dedupes_repeated_polls(monkeypatch, client):
    tenant = 'dedupe-tenant'
    def _fetch(self, since_ts=None):
        return iter([{'source': 'azure_entra_signin', 'actor': 'alice@example.com', 'ip': '203.0.113.5', 'ts': '2026-01-01T00:00:00Z', 'id': 'evt-repeat'}])

    from src.api.routes.connectors import EntraIDConnector as _EntraID
    monkeypatch.setattr(_EntraID, 'fetch_signins', _fetch)
    client.put(
        f'/api/v1/connectors/{tenant}/azure/entra_signin/config',
        headers=_headers(),
        json={'config': {'tenant_id': 'tenant-123', 'client_id': 'cid', 'client_secret': 'secret', 'auth_mode': 'client_secret'}},
    )
    first = client.post(f'/api/v1/connectors/{tenant}/azure/entra_signin/poll', headers=_headers(), json={'since_ts': 0})
    second = client.post(f'/api/v1/connectors/{tenant}/azure/entra_signin/poll', headers=_headers(), json={'since_ts': 0})
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()['ingested'] == 1
    assert second.json()['ingested'] == 0
    assert second.json()['duplicates_suppressed'] == 1


def test_connector_circuit_state_surfaces_on_repeated_failure(monkeypatch, client):
    tenant = 'circuit-tenant'
    def _fail(self, since_ts=None):
        raise RuntimeError('boom')

    from src.api.routes.connectors import EntraIDConnector as _EntraID
    monkeypatch.setattr(_EntraID, 'fetch_signins', _fail)
    client.put(
        f'/api/v1/connectors/{tenant}/azure/entra_signin/config',
        headers=_headers(),
        json={'config': {'tenant_id': 'tenant-123', 'client_id': 'cid', 'client_secret': 'secret', 'auth_mode': 'client_secret'}},
    )
    for _ in range(3):
        resp = client.post(f'/api/v1/connectors/{tenant}/azure/entra_signin/poll', headers=_headers(), json={'since_ts': 0})
        assert resp.status_code == 502
    dry = client.post(f'/api/v1/connectors/{tenant}/azure/entra_signin/poll', headers=_headers(), json={'dry_run': True})
    assert dry.status_code == 200
    assert dry.json()['runtime_state']['consecutive_failures'] >= 3
