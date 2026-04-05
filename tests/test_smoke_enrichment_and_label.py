import time
import json
from fastapi.testclient import TestClient
from src.api.server import app, DECISION_CACHE
import os


def test_smoke_enrichment_and_label(monkeypatch):
    client = TestClient(app)
    # Make sure the canonical pytest API key is recognized by auth_dependency
    os.environ['API_KEYS_JSON'] = json.dumps([{"key": "testkey123", "scopes": ["feedback.write", "factors.search"]}])
    # Also import expanded rules to ensure registration
    try:
        from src.core.correlation.rules.weekX import expanded_batch  # type: ignore
    except Exception:
        pass
    # Monkeypatch auth to allow labeling endpoint in test environment
    def _noop_require_scopes(scope: str):
        def _inner(*a, **k):
            return True
        return _inner

    monkeypatch.setattr('security.auth.require_scopes', _noop_require_scopes)
    # Minimal event that should trigger one of the Batch 3 rules (e.g., c2_rare_ja3_beacon)
    payload = {
        "events": [
            {
                "id": "smoke-evt-1",
                "host": "smoke-host-1",
                "timestamp": "2025-10-12T13:30:00Z",
                "net:outbound_ja3_rare": True,
                "beacon_like_periodicity": True
            }
        ],
        "include_rules": True,
        "classify": True,
        "send_alerts": False
    }
    r = client.post('/api/v1/endpoints/log_batch', json=payload)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get('accepted') == 1
    ev = j.get('events')[0]
    # Expect verdict field present and score
    assert 'verdict' in ev
    # Now label the decision as true positive via operator endpoint
    event_id = 'smoke-evt-1'
    label_payload = {'label': 'tp', 'rule': 'c2_rare_ja3_beacon', 'comment': 'smoke test TP'}
    # Use the test API key accepted by auth_dependency when running under pytest
    headers = {'x-api-key': 'testkey123'}
    r2 = client.post(f'/api/v1/decisions/{event_id}/label', json=label_payload, headers=headers)
    assert r2.status_code == 200, r2.text
    assert r2.json().get('ok') is True
