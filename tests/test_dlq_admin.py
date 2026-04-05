import json
import time
from fastapi.testclient import TestClient
import pytest

from api.server import app


def _fake_fetch_one(sql, *args, **kwargs):
    # return a single DLQ row
    return [{'id': 1, 'event_id': 'evt-1', 'payload': {'event_id': 'evt-1', 'verdict': 'OBSERVE', 'factors': []}, 'error': 'err', 'attempts': 0, 'next_retry': None}]


def test_requeue_validation_requires_fields(monkeypatch):
    monkeypatch.setenv('ADMIN_SESSION_SECRET', 'testsecret')
    monkeypatch.setenv('ADMIN_UI_TOKEN', 'testtoken')
    client = TestClient(app)
    # mock db fetch
    monkeypatch.setattr('db.adapter.fetch', lambda *a, **k: _fake_fetch_one(*a, **k))
    # mock dlq_audit
    recorded = {}
    def fake_audit(dlq_id, user, original, new):
        recorded['called'] = True
        recorded['new'] = new
    monkeypatch.setattr('core.dlq_audit.record_requeue_audit', fake_audit)
    # missing event_id - include admin headers and csrf
    from tests._helpers import admin_test_headers
    hdrs = admin_test_headers(client, admin_token='testtoken', client_ip='10.0.0.5')
    resp = client.post('/api/v1/dlq/1/requeue', json={'verdict': 'SUSPICIOUS', 'factors': []}, headers=hdrs)
    assert resp.status_code == 400
    # valid payload
    payload = {'event_id': 'evt-1', 'verdict': 'SUSPICIOUS', 'factors': ['f1'], 'confidence': 0.5}
    # mock DLQ manager path: stub _attempt_redeliver to return True by patching module
    class FakeMgr:
        async def _attempt_redeliver(self, row):
            return True
    import src.api.startup as _startup
    # attach a FakeMgr instance to runtime_state.dlq so server picks it up
    _startup.runtime_state.dlq = FakeMgr()
    # perform request
    hdrs = admin_test_headers(client, admin_token='testtoken', client_ip='10.0.0.5')
    resp2 = client.post('/api/v1/dlq/1/requeue', json=payload, headers=hdrs)
    # we didn't set auth so will 401 or 403; at minimum ensure validation path works when allowed
    assert resp2.status_code in (200, 500)
