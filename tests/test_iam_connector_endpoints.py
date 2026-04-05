import json
import os
import time
from pathlib import Path

import pytest

from src.api.runtime_state import get_server_runtime_state

API_KEY = os.environ.get('TEST_API_KEY', 'devkey123')
TEST_CFG = Path('artifacts/config/iam_connectors_test.json')
os.environ['IAM_CONNECTORS_PATH'] = str(TEST_CFG)
os.environ.setdefault('IAM_CONNECTOR_MISSING_TTL', '3600')
os.environ.setdefault('IAM_CONNECTOR_DEFAULTS_JSON', json.dumps({'default': {'azure_ad': {'tenant_id': 'env-default'}}}))


@pytest.fixture(scope='module', autouse=True)
def cleanup():
    if TEST_CFG.exists():
        TEST_CFG.unlink()
    yield
    if TEST_CFG.exists():
        TEST_CFG.unlink()


@pytest.fixture(scope='module')
def client():
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    from src.api.app import create_app
    # Use the factory to ensure deterministic initialization under pytest
    app = create_app({'mode': 'test'})
    from fastapi.testclient import TestClient
    # Diagnostic: print app identity and route presence when running under pytest
    try:
        import sys as _sys, json as _json
        print('\n[TEST DIAG] client fixture: app id =>', id(app))
        try:
            rts = sorted({getattr(r, 'path', str(r)) for r in app.router.routes})
        except Exception:
            rts = sorted({getattr(r, 'path', str(r)) for r in app.routes})
        print('[TEST DIAG] routes count =>', len(rts))
        print('[TEST DIAG] connectors/status present =>', '/api/v1/iam/connectors/status' in rts)
        iam_routes = [p for p in rts if p and p.startswith('/api/v1/iam')]
        print('[TEST DIAG] iam routes (count {}) =>'.format(len(iam_routes)), iam_routes)
        mods = [k for k in _sys.modules.keys() if k.endswith('api.app') or 'api.app' in k]
        print('[TEST DIAG] api.app modules in sys.modules =>', _json.dumps(mods))
        for m in mods:
            try:
                modobj = _sys.modules.get(m)
                print(f'[TEST DIAG] mod {m} id ->', id(modobj))
                try:
                    print(f'[TEST DIAG]   {m}.app id ->', id(getattr(modobj, 'app')))
                except Exception:
                    print(f'[TEST DIAG]   {m}.app -> <no app attr>')
            except Exception:
                pass
    except Exception as _e:
        print('[TEST DIAG] client fixture diagnostic failed:', _e)
    return TestClient(app)


def _headers():
    return {'x-api-key': API_KEY, 'Content-Type': 'application/json'}


def test_list_connectors(client):
    resp = client.get('/api/v1/iam/connectors/status', headers=_headers())
    assert resp.status_code == 200
    data = resp.json()
    assert 'connectors' in data
    ids = {c['id'] for c in data['connectors']}
    assert 'okta' in ids
    assert 'azure_ad' in ids


def test_save_okta_credentials_masked(client):
    payload = {
        'connector': 'okta',
        'tenant_id': 'default',
        'config': {'org_url': 'https://acme.okta.com', 'api_token': 'ssws-123'},
    }
    resp = client.post('/api/v1/iam/connectors/config', headers=_headers(), data=json.dumps(payload))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data['saved'] is True
    status = client.get('/api/v1/iam/connectors/status', headers=_headers()).json()
    okta = next(c for c in status['connectors'] if c['id'] == 'okta')
    assert okta['config']['org_url'] == 'https://acme.okta.com'
    assert okta['config']['api_token']['present'] is True
    # ensure file stored real secret
    raw = json.loads(TEST_CFG.read_text(encoding='utf-8'))
    stored = raw['tenants']['default']['okta']
    assert stored['api_token'] == 'ssws-123'


def test_secret_not_overwritten_when_blank(client):
    payload = {
        'connector': 'okta',
        'tenant_id': 'default',
        'config': {'org_url': 'https://corp.okta.com'},
    }
    resp = client.post('/api/v1/iam/connectors/config', headers=_headers(), data=json.dumps(payload))
    assert resp.status_code == 200
    raw = json.loads(TEST_CFG.read_text(encoding='utf-8'))
    stored = raw['tenants']['default']['okta']
    assert stored['api_token'] == 'ssws-123'
    assert stored['org_url'] == 'https://corp.okta.com'


def test_secret_saved_with_vault_backend(monkeypatch, tmp_path, client):
    vault_file = tmp_path / 'vault_store.json'
    monkeypatch.setenv('VAULT_BACKEND', 'file')
    monkeypatch.setenv('VAULT_FILE_PATH', str(vault_file))
    payload = {
        'connector': 'okta',
        'tenant_id': 'vaulttenant',
        'config': {'org_url': 'https://vault.okta.com', 'api_token': 'vault-secret-123'},
    }
    resp = client.post('/api/v1/iam/connectors/config', headers=_headers(), data=json.dumps(payload))
    assert resp.status_code == 200
    data = resp.json()
    assert data['saved'] is True
    stored = json.loads(TEST_CFG.read_text(encoding='utf-8'))
    secret_entry = stored['tenants']['vaulttenant']['okta']['api_token']
    assert isinstance(secret_entry, dict)
    vault_key = secret_entry.get('_vault_key')
    assert vault_key and vault_key.startswith('iam/')
    secrets_on_disk = json.loads(vault_file.read_text(encoding='utf-8'))
    assert secrets_on_disk[vault_key] == 'vault-secret-123'


def test_env_defaults_seeded(client):
    resp = client.get('/api/v1/iam/connectors/status', headers=_headers())
    assert resp.status_code == 200
    data = resp.json()
    azure = next(c for c in data['connectors'] if c['id'] == 'azure_ad')
    assert azure['config']['tenant_id'] == 'env-default'
    assert azure['config_source'] in ('default', 'saved')


def test_connector_health_reporting(client):
    payload = {
        "data": {
            "events": [
                {
                    "eventType": "user.session.start",
                    "published": "2025-01-01T00:00:00Z",
                    "actor": {"alternateId": "bob@example.com"},
                    "client": {"ipAddress": "1.2.3.4"}
                }
            ]
        }
    }
    resp = client.post('/api/v1/iam/okta/webhook', headers={'x-api-key': API_KEY}, json=payload)
    assert resp.status_code == 200
    resp = client.get('/api/v1/iam/connectors/status?include_health=1', headers=_headers())
    assert resp.status_code == 200
    data = resp.json()
    okta = next(c for c in data['connectors'] if c['id'] == 'okta')
    health = okta['health']
    assert health is not None
    assert health['missing_log'] is False
    assert health['total_ingested'] >= 1


def test_missing_alerts_surface_when_ttl_expires(client):
    runtime = get_server_runtime_state(client.app)
    tmap = runtime.tenants.setdefault('default', {})
    health = tmap.setdefault('iam_connector_health', {})
    health['okta'] = {'last_event_ts': time.time() - 900, 'total_ingested': 10}
    resp = client.get('/api/v1/iam/connectors/status?include_health=1', headers=_headers())
    assert resp.status_code == 200
    data = resp.json()
    alerts = data.get('missing_alerts') or []
    assert alerts, 'Expected missing alert for idle Okta connector'
    okta_alert = next(a for a in alerts if a['connector'] == 'okta')
    assert okta_alert['severity'] in {'warning', 'high', 'critical'}
    assert okta_alert['ttl_seconds'] > 0


def test_missing_alerts_include_ticket_metadata(monkeypatch, client):
    runtime = get_server_runtime_state(client.app)
    tmap = runtime.tenants.setdefault('default', {})
    health = tmap.setdefault('iam_connector_health', {})
    health['okta'] = {'last_event_ts': time.time() - 900, 'total_ingested': 10}

    async def fake_dispatch(tenant, runtime_health, missing_alerts):
        return [
            {
                'connector': 'okta',
                'auto_ticket': {
                    'status': 'triggered',
                    'action': 'ticket.create',
                    'result': {
                        'providers': [
                            {'provider': 'cortex', 'result': {'status': 'ok'}},
                            {'provider': 'phantom', 'error': 'timeout'},
                        ]
                    },
                },
            }
        ]

    monkeypatch.setattr('src.api.iam_connector_endpoints.dispatch_missing_log_alerts', fake_dispatch)
    resp = client.get('/api/v1/iam/connectors/status?include_health=1', headers=_headers())
    assert resp.status_code == 200
    data = resp.json()
    alerts = data.get('missing_alerts') or []
    okta_alert = next(a for a in alerts if a['connector'] == 'okta')
    assert 'auto_ticket' in okta_alert
    providers = okta_alert['auto_ticket']['result']['providers']
    assert providers[0]['provider'] == 'cortex'
    assert providers[1]['error'] == 'timeout'


@pytest.mark.asyncio
async def test_missing_log_auto_ticket(monkeypatch):
    from src.services import missing_log_monitor as monitor

    class StubClient:
        def __init__(self):
            self.tickets = []
            self.alerts = []

        async def create_alert(self, title, severity, details):
            self.alerts.append((title, severity, details))
            return {}

        async def execute_action(self, action, target, params):
            self.tickets.append((action, target, params))
            return {'ok': True}

    stub = StubClient()
    monkeypatch.setenv('IAM_MISSING_LOG_AUTO_TICKET', '1')
    monkeypatch.setenv('IAM_MISSING_LOG_AUTO_TICKET_THRESHOLD', '2')
    monkeypatch.setenv('IAM_MISSING_LOG_AUTO_TICKET_COOLDOWN', '0')
    monkeypatch.setattr(monitor, 'get_soar_client', lambda: stub)
    runtime = {'okta': {}}
    alert = {'connector': 'okta', 'label': 'Okta', 'severity': 'critical', 'seconds_since_event': 600, 'ttl_seconds': 300, 'recommendations': []}
    await monitor.dispatch_missing_log_alerts('tenant-auto', runtime, [alert])
    assert not stub.tickets
    await monitor.dispatch_missing_log_alerts('tenant-auto', runtime, [alert])
    assert len(stub.tickets) == 1
    action, target, params = stub.tickets[0]
    assert target == 'okta'
    assert action == os.getenv('IAM_MISSING_LOG_AUTO_TICKET_ACTION', 'ticket.create')


def test_heartbeat_override_round_trip(client):
    payload = {'connector': 'okta', 'tenant_id': 'default', 'ttl_seconds': 180}
    resp = client.post('/api/v1/iam/connectors/heartbeat', headers=_headers(), data=json.dumps(payload))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data['overridden'] is True
    assert round(data['ttl_seconds']) == 180
    raw = json.loads(TEST_CFG.read_text(encoding='utf-8'))
    assert raw['settings']['default']['ttl_overrides']['okta'] == 180

    # Reset to default
    reset_payload = {'connector': 'okta', 'tenant_id': 'default', 'ttl_seconds': None}
    resp = client.post('/api/v1/iam/connectors/heartbeat', headers=_headers(), data=json.dumps(reset_payload))
    assert resp.status_code == 200
    data = resp.json()
    assert data['overridden'] is False
    raw = json.loads(TEST_CFG.read_text(encoding='utf-8'))
    overrides = raw['settings']['default'].get('ttl_overrides', {})
    assert 'okta' not in overrides
