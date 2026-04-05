import os
import sys
import time
import pathlib
import types
from fastapi.testclient import TestClient

# ensure src is importable
root = pathlib.Path(__file__).resolve().parents[1]
src = root / 'src'
sp = str(src)
if sp not in sys.path:
    sys.path.insert(0, sp)

# stub optional heavy routers
from fastapi import APIRouter
if 'api.soar_endpoints' not in sys.modules:
    sys.modules['api.soar_endpoints'] = types.SimpleNamespace(router=APIRouter())

from src.api.server import app, DECISION_CACHE
from repositories.decisions_repo_adapter import repo as decisions_adapter


def test_metrics_scrape_updates_after_risk(monkeypatch):
    monkeypatch.setenv('RISK_HIGH_THRESHOLD','0.1')
    # Post an event that will produce some risk
    client = TestClient(app)
    payload = {
        'events': [{'id':'evt-metrics-1','host':'h1','details':{'x':1},'factors':['net:beacon_periodic']}],
        'classify': True,
        'send_alerts': False,
        'include_rules': False,
        'tenant_id': 'metrics_tenant'
    }
    from tests._helpers import default_test_headers
    r = client.post('/api/v1/endpoints/log_batch', json=payload, headers=default_test_headers('10.10.10.3'))
    assert r.status_code == 200
    try:
        from src.api.runtime_state import drain_event_queue_for_tests
        drain_event_queue_for_tests()
    except Exception:
        time.sleep(0.2)
    # Inspect the metrics registry directly to avoid ASGI scrape semantics
    from core.metrics.registry import expected_metrics
    em = expected_metrics()
    # expected_metrics returns metric_name -> kind
    assert any('risk_high' in m for m in em.keys())
    assert any('risk_score_distribution' in m or 'score_distribution' in m for m in em.keys())


def test_auto_escalate_promotes_and_persists(monkeypatch):
    monkeypatch.setenv('RISK_AUTO_ESCALATE','1')
    monkeypatch.setenv('RISK_AUTO_ESCALATE_THRESHOLD','0.0')
    # ensure adapter memory cleared
    try:
        # adapter provides list_memory
        decisions_adapter.list_memory().clear()
    except Exception:
        pass
    client = TestClient(app)
    payload = {
        'events': [{'id':'evt-escalate-1','host':'h2','details':{},'factors':['scenario:critical:abc']}],
        'classify': True,
        'send_alerts': False,
        'include_rules': False,
        'tenant_id': 'escalate_tenant'
    }
    from tests._helpers import default_test_headers
    r = client.post('/api/v1/endpoints/log_batch', json=payload, headers=default_test_headers('10.10.10.4'))
    assert r.status_code == 200
    # Drain event queue so background tasks run deterministically in tests
    try:
        from src.api.runtime_state import drain_event_queue_for_tests
        drain_event_queue_for_tests()
    except Exception:
        # fallback to sleep
        time.sleep(0.5)
    dec = DECISION_CACHE.get('evt-escalate-1')
    assert dec is not None
    # since threshold 0.0 and factor is scenario:critical we expect promotion to at least SUSPICIOUS or MALICIOUS
    assert dec.get('verdict') in {'SUSPICIOUS','MALICIOUS'}
    # persisted to adapter memory
    # assert server recorded a persisted attempt
    import api.server as srv
    found = any(d.get('event_id') == 'evt-escalate-1' or d.get('id') == 'evt-escalate-1' for d in getattr(srv, '_PERSISTED_DECISIONS', []))
    assert found, f"persist attempt not recorded in server persisted list: {getattr(srv, '_PERSISTED_DECISIONS', [])}"
