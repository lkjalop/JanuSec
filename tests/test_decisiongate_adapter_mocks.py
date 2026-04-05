import pytest
import asyncio
from starlette.testclient import TestClient
from src.api.app import create_app

app = create_app({'mode': 'test'})


class DummyXDR:
    async def block_ip_address(self, ip, hours):
        # simulate success
        return {'success': True, 'blocked_ip': ip, 'duration_hours': hours}

    async def isolate_endpoint(self, endpoint, reason):
        return {'success': True, 'isolated': endpoint, 'reason': reason}

class DummyTicketing:
    async def create_security_ticket(self, title, desc, sev, assignee):
        if 'fail' in title.lower():
            return {'success': False, 'error': 'ticket_creation_failed'}
        return {'success': True, 'ticket_id': 'TCKT-1234', 'title': title}

class DummyEngine:
    def __init__(self):
        self.xdr_integration = DummyXDR()
        self.ticketing = DummyTicketing()
        self.notification_service = type('N', (), {'send_slack_notification': lambda *a, **k: {'success': True}})()

    async def initialize(self):
        return True


@pytest.fixture(autouse=True)
def patch_engine(monkeypatch):
    # Ensure admin key check passes
    monkeypatch.setenv('ADMIN_API_KEY', 'adminkey')
    # Patch _get_soar_engine to return our dummy engine
    async def _fake_get(app):
        eng = DummyEngine()
        return eng
    from src.api.ingest_controller_endpoints import _get_soar_engine
    monkeypatch.setattr('src.api.ingest_controller_endpoints._get_soar_engine', _fake_get)
    yield


def test_block_ip_success(monkeypatch):
    client = TestClient(app)
    payload = {'actor': 'tester', 'action': 'block_ip', 'args': {'ip': '1.2.3.4', 'duration_hours': 12}}
    r = client.post('/api/v1/ingest/decision/execute', json=payload, headers={'x-api-key': 'adminkey'})
    assert r.status_code == 200
    det = r.json().get('detail') or {}
    assert det.get('result', {}).get('success') is True
    assert det.get('result', {}).get('blocked_ip') == '1.2.3.4'


def test_create_ticket_success_and_failure(monkeypatch):
    client = TestClient(app)
    # success
    payload_ok = {'actor': 'tester', 'action': 'create_ticket', 'args': {'title': 'Incident: suspicious', 'description': 'desc', 'severity': 'high'}}
    r_ok = client.post('/api/v1/ingest/decision/execute', json=payload_ok, headers={'x-api-key': 'adminkey'})
    assert r_ok.status_code == 200
    det_ok = r_ok.json().get('detail') or {}
    assert det_ok.get('result', {}).get('success') is True
    assert 'ticket_id' in det_ok.get('result', {})

    # failure path simulated by title containing 'fail'
    payload_fail = {'actor': 'tester', 'action': 'create_ticket', 'args': {'title': 'FAIL ticket', 'description': 'desc', 'severity': 'high'}}
    r_f = client.post('/api/v1/ingest/decision/execute', json=payload_fail, headers={'x-api-key': 'adminkey'})
    assert r_f.status_code == 200
    det_f = r_f.json().get('detail') or {}
    # engine returned success False; top-level status should reflect failure
    assert det_f.get('result', {}).get('success') is False
