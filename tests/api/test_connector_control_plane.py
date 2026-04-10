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
    status_payload = s.json()['status']
    assert status_payload['last_count'] == 1
    assert status_payload['authenticated'] is True
    assert status_payload['receiving_events'] is True
    assert 'checkpoint_healthy' in status_payload
    assert 'freshness' in status_payload


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
    payload = status.json()['status']
    assert payload['ok'] is True
    assert 'beta_ready' in payload


def test_connector_poll_and_status_for_okta(monkeypatch, client):
    def _fetch(self, since_ts):
        return [{'uuid': 'okta-evt-1', 'published': '2026-01-01T00:00:00Z', 'eventType': 'user.authentication.failed', 'actor': {'alternateId': 'alice@example.com'}, 'client': {'ipAddress': '203.0.113.9'}}]

    from src.api.routes.connectors import OktaIAMCollector as _Okta
    monkeypatch.setattr(_Okta, 'fetch_events', _fetch)
    cfg = client.put(
        '/api/v1/connectors/default/okta/okta/config',
        headers=_headers(),
        json={'config': {'org_url': 'https://acme.okta.com', 'api_token': 'ssws-123'}},
    )
    assert cfg.status_code == 200
    r = client.post('/api/v1/connectors/default/okta/okta/poll', headers=_headers(), json={'since_ts': 0})
    assert r.status_code == 200, r.text
    assert r.json()['ingested'] == 1
    status = client.get('/api/v1/connectors/default/okta/okta/status', headers=_headers())
    assert status.status_code == 200
    payload = status.json()['status']
    assert payload['ok'] is True
    assert payload['authenticated'] is True
    assert payload['receiving_events'] is True


def test_connector_poll_and_status_for_sailpoint(monkeypatch, client):
    async def _poll(self):
        return [{'id': 'sp-evt-1', 'created': '2026-01-01T00:00:00Z', 'type': 'privilege-change', 'actor': {'name': 'alice@example.com'}, 'target': {'name': 'admin-role'}, 'operation': 'privilege-change'}]

    from src.api.routes.connectors import SailPointCollector as _SailPoint
    monkeypatch.setattr(_SailPoint, 'poll_events', _poll)
    cfg = client.put(
        '/api/v1/connectors/default/sailpoint/sailpoint/config',
        headers=_headers(),
        json={'config': {'base_url': 'https://tenant.api.identitynow.com', 'client_id': 'cid', 'client_secret': 'secret'}},
    )
    assert cfg.status_code == 200
    r = client.post('/api/v1/connectors/default/sailpoint/sailpoint/poll', headers=_headers(), json={'since_ts': 0})
    assert r.status_code == 200, r.text
    assert r.json()['ingested'] == 1
    status = client.get('/api/v1/connectors/default/sailpoint/sailpoint/status', headers=_headers())
    assert status.status_code == 200
    assert status.json()['status']['ok'] is True


def test_connector_poll_and_status_for_email_connectors(monkeypatch, client):
    async def _mime_execute(self, domain, entity, window=None, context=None):
        return {'events': [{'id': 'mime-1', 'Datetime': '2026-01-01T00:00:00Z', 'Sender': 'attacker@example.com', 'Recipients': ['bob@example.com'], 'Act': 'BLOCK'}]}

    async def _proof_execute(self, domain, entity, window=None, context=None):
        return {'events': [{'id': 'pp-1', 'clickTime': '2026-01-01T00:00:00Z', 'recipient': 'bob@example.com', 'sender': 'attacker@example.com', 'threatsInfoMap': [{'threatType': 'malware'}]}]}

    from src.api.routes.connectors import MimecastConnector as _Mimecast, ProofpointConnector as _Proofpoint
    monkeypatch.setattr(_Mimecast, 'execute', _mime_execute)
    monkeypatch.setattr(_Proofpoint, 'execute', _proof_execute)

    mime_cfg = client.put(
        '/api/v1/connectors/default/email/mimecast/config',
        headers=_headers(),
        json={'config': {'client_id': 'cid', 'client_secret': 'secret', 'token_url': 'https://mimecast.example/token'}},
    )
    assert mime_cfg.status_code == 200
    mime_poll = client.post('/api/v1/connectors/default/email/mimecast/poll', headers=_headers(), json={'since_ts': 0})
    assert mime_poll.status_code == 200, mime_poll.text
    assert mime_poll.json()['ingested'] == 1

    proof_cfg = client.put(
        '/api/v1/connectors/default/email/proofpoint/config',
        headers=_headers(),
        json={'config': {'client_id': 'cid', 'client_secret': 'secret', 'token_url': 'https://proofpoint.example/token'}},
    )
    assert proof_cfg.status_code == 200
    proof_poll = client.post('/api/v1/connectors/default/email/proofpoint/poll', headers=_headers(), json={'since_ts': 0})
    assert proof_poll.status_code == 200, proof_poll.text
    assert proof_poll.json()['ingested'] == 1


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
