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


def test_okta_webhook_verification(client):
    resp = client.post('/api/v1/iam/okta/webhook', headers=_headers(), json={'verification': 'abc123'})
    assert resp.status_code == 200
    assert resp.json() == {'verification': 'abc123'}


def test_okta_webhook_ingest(client):
    payload = {
        "data": {
            "events": [
                {
                    "eventType": "user.session.start",
                    "published": "2025-01-01T00:00:00Z",
                    "actor": {"alternateId": "alice@example.com"},
                    "client": {"ipAddress": "203.0.113.5"}
                }
            ]
        }
    }
    resp = client.post('/api/v1/iam/okta/webhook', headers=_headers(), json=payload)
    assert resp.status_code == 200
    assert resp.json()['ingested'] == 1
    runtime = get_server_runtime_state(client.app)
    events = runtime.tenants.setdefault('default', {}).get('recent_iam_events')
    assert events
    assert events[-1]['provider'] == 'okta'
    assert events[-1]['actor'] == 'alice@example.com'


def test_okta_poll_uses_collector(monkeypatch, client):
    class DummyCollector:
        def __init__(self, tenant_id='default'):
            self.tenant_id = tenant_id

        def fetch_events(self, since_ts):
            return [{
                "eventType": "user.account.update",
                "published": "2025-01-02T00:00:00Z",
                "actor": {"alternateId": "svc@example.com"},
                "client": {"ipAddress": "198.51.100.10"}
            }]

    monkeypatch.setattr('src.api.iam_ingest_endpoints.OktaIAMCollector', DummyCollector)
    resp = client.post('/api/v1/iam/okta/poll', headers=_headers(), json={'since_ts': 0})
    assert resp.status_code == 200
    assert resp.json()['ingested'] == 1


def test_azure_webhook_validation(client):
    resp = client.get('/api/v1/iam/azure/webhook', params={'validationToken': 'token-xyz'})
    assert resp.status_code == 200
    assert resp.text == 'token-xyz'


def test_azure_webhook_ingest(client):
    payload = {
        "value": [
            {
                "resourceData": {
                    "id": "aad-1",
                    "activityDateTime": "2025-01-03T00:00:00Z",
                    "initiatedBy": {"user": {"userPrincipalName": "bob@example.com", "ipAddress": "192.0.2.33"}},
                    "activityDisplayName": "UserLoggedIn",
                    "status": {"errorCode": 0}
                }
            }
        ]
    }
    resp = client.post('/api/v1/iam/azure/webhook', headers=_headers(), json=payload)
    assert resp.status_code == 200
    assert resp.json()['ingested'] == 1
    runtime = get_server_runtime_state(client.app)
    events = runtime.tenants.setdefault('default', {}).get('recent_iam_events')
    assert events
    assert events[-1]['provider'] == 'azure_ad'


def test_azure_poll_uses_collector(monkeypatch, client):
    class DummyCollector:
        def fetch_events(self, since_ts):
            return [{
                "id": "aad-2",
                "activityDateTime": "2025-01-04T00:00:00Z",
                "initiatedBy": {"user": {"userPrincipalName": "carol@example.com", "ipAddress": "198.51.100.22"}},
                "activityDisplayName": "RoleUpdate",
                "status": {"errorCode": 0}
            }]

    monkeypatch.setattr('src.api.iam_ingest_endpoints.AzureADCollector', DummyCollector)
    resp = client.post('/api/v1/iam/azure/poll', headers=_headers(), json={'since_ts': 0})
    assert resp.status_code == 200
    assert resp.json()['ingested'] == 1
