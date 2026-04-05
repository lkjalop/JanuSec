import os

import pytest
from fastapi.testclient import TestClient

from src.api.runtime_state import get_server_runtime_state

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


def test_connector_poll_and_status_for_aws(monkeypatch, client):
    def _fetch(self, start_time=None):
        return iter([{'source': 'cloudtrail', 'id': 'evt-1', 'ts': 123, 'account_id': '123'}])

    from src.api.routes.connectors import CloudTrailConnector as _CTC
    monkeypatch.setattr(_CTC, 'fetch_events', _fetch)

    r = client.post('/api/v1/connectors/default/aws/cloudtrail/poll', headers=_headers(), json={'since_ts': 0})
    assert r.status_code == 200
    body = r.json()
    assert body['ingested'] == 1

    runtime = get_server_runtime_state(client.app)
    status = runtime.tenants['default']['connector_health']['aws:cloudtrail']
    assert status['last_count'] == 1
    assert status['ok'] is True

    s = client.get('/api/v1/connectors/default/aws/cloudtrail/status', headers=_headers())
    assert s.status_code == 200
    assert s.json()['status']['last_count'] == 1


def test_connector_poll_and_status_for_azure(monkeypatch, client):
    def _fetch_signins(self, since_ts=None):
        return iter([{'source': 'azure_entra_signin', 'actor': 'alice@example.com', 'ts': '2026-01-01T00:00:00Z'}])

    from src.api.routes.connectors import EntraIDConnector as _EntraID
    monkeypatch.setattr(_EntraID, 'fetch_signins', _fetch_signins)
    cfg = client.put(
        '/api/v1/connectors/default/azure/entra_signin/config',
        headers=_headers(),
        json={'config': {'tenant_id': 'tenant-123', 'client_id': 'cid', 'client_secret': 'secret', 'auth_mode': 'client_secret'}},
    )
    assert cfg.status_code == 200

    r = client.post('/api/v1/connectors/default/azure/entra_signin/poll', headers=_headers(), json={'since_ts': 0})
    assert r.status_code == 200
    body = r.json()
    assert body['ingested'] == 1

    status = client.get('/api/v1/connectors/default/azure/entra_signin/status', headers=_headers())
    assert status.status_code == 200
    assert status.json()['status']['ok'] is True


def test_status_connectors_endpoint_uses_runtime_health(client):
    r = client.get('/api/v1/status/connectors', headers={'x-tenant-id': 'default'})
    assert r.status_code == 200
    connectors = r.json()['connectors']
    names = {entry['name'] for entry in connectors}
    assert 'aws:cloudtrail' in names or 'azure:entra_signin' in names


def test_status_connectors_includes_runtime_projection_fields(monkeypatch, client):
    def _fetch(self, start_time=None):
        return iter([
            {'source': 'cloudtrail', 'id': 'evt-dupe', 'ts': 123, 'account_id': '123'},
            {'source': 'cloudtrail', 'id': 'evt-dupe', 'ts': 123, 'account_id': '123'},
        ])

    from src.api.routes.connectors import CloudTrailConnector as _CTC
    monkeypatch.setattr(_CTC, 'fetch_events', _fetch)
    poll = client.post('/api/v1/connectors/default/aws/cloudtrail/poll', headers=_headers(), json={'since_ts': 0})
    assert poll.status_code == 200

    r = client.get('/api/v1/status/connectors', headers={'x-tenant-id': 'default'})
    assert r.status_code == 200
    connectors = {entry['name']: entry for entry in r.json()['connectors']}
    entry = connectors['aws:cloudtrail']
    assert 'last_duplicate_count' in entry
    assert 'last_latency_ms' in entry
    assert 'runtime_state' in entry
    assert 'circuit_open' in entry
