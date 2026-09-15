from __future__ import annotations

from fastapi.testclient import TestClient

from src.api.app import app
from src.api import runtime_state


def test_ingestion_includes_compliance_controls(monkeypatch):
    # Seed runtime decision cache with factors that map to controls
    try:
        runtime_state.DECISION_CACHE.clear()
    except Exception:
        try:
            for k in list(runtime_state.DECISION_CACHE.keys()):
                runtime_state.DECISION_CACHE.pop(k, None)
        except Exception:
            pass
    runtime_state.cache_set('evt1', {'event_id': 'evt1', 'verdict': 'suspicious', 'confidence': 0.8, 'factors': ['cloud:public_bucket']})
    runtime_state.cache_set('evt2', {'event_id': 'evt2', 'verdict': 'malicious', 'confidence': 0.95, 'factors': ['iam:key_no_mfa']})

    client = TestClient(app)
    r = client.get('/api/v1/report/ingestion?format=json', headers={'x-api-key': 'devkey123'})
    assert r.status_code == 200
    j = r.json()
    assert 'compliance_controls' in j
    ctrls = j['compliance_controls'].get('controls') or []
    # Expect at least CIS-AWS and ISO/NIST codes from factor mappings
    assert any(c.startswith('CIS-') for c in ctrls)
    assert any(c.startswith('ISO') for c in ctrls)
    assert any(c.startswith('NIST') for c in ctrls)

