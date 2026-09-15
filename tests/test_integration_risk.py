import os
import sys
import time
import pathlib
import json
from fastapi.testclient import TestClient

# Ensure src is importable when running this test directly
root = pathlib.Path(__file__).resolve().parents[1]
src = root / 'src'
sp = str(src)
if sp not in sys.path:
    sys.path.insert(0, sp)

# Provide lightweight stubs for optional routers that perform relative imports
import types
from fastapi import APIRouter
if 'api.soar_endpoints' not in sys.modules:
    sys.modules['api.soar_endpoints'] = types.SimpleNamespace(router=APIRouter())

from api.server import app, DECISION_CACHE


def test_pipeline_attaches_risk(monkeypatch):
    # deterministic env
    monkeypatch.setenv('RISK_HIGH_THRESHOLD','0.5')
    monkeypatch.setenv('RISK_AUTO_ESCALATE','0')
    client = TestClient(app)
    event = {
        'id': 'evt-integ-1',
        'host': 'host1',
        'details': {'cmdline': 'curl bad.com'},
    }
    payload = {
        'events': [event],
        'classify': True,
        'send_alerts': False,
        'include_rules': False,
        'tenant_id': 'test'
    }
    from tests._helpers import default_test_headers
    resp = client.post('/api/v1/endpoints/log_batch', json=payload, headers=default_test_headers('10.10.10.1'))
    assert resp.status_code == 200
    body = resp.json()
    assert body['accepted'] == 1
    # Drain the in-process event queue so background ingestion runs deterministically
    try:
        from src.api.runtime_state import drain_event_queue_for_tests
        drain_event_queue_for_tests()
    except Exception:
        # fallback to small sleep if helper unavailable
        time.sleep(0.05)
    dec = DECISION_CACHE.get('evt-integ-1')
    assert dec is not None
    # risk payload should be present
    assert 'risk_score' in dec
    assert 'risk_breakdown' in dec
    assert isinstance(dec['risk_breakdown'], list)
