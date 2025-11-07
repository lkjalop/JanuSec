import time
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.incidents.aggregator import GLOBAL_INCIDENTS


def test_auto_generated_incident_created(monkeypatch):
    app = create_app()
    client = TestClient(app)

    # ensure aggregator is clean
    GLOBAL_INCIDENTS.clear()

    # Build a minimal payload that should trigger auto-gen logic
    payload = {
        "session_id": "test-session-auto-1",
        "batches": [
            {"batch_id": "b1", "events": [{"id": "e1", "source_ip": "10.0.0.5", "dst_ip": "8.8.8.8"}]},
            {"batch_id": "b2", "events": [{"id": "e2", "source_ip": "10.0.0.9", "dst_ip": "8.8.4.4"}]}
        ],
        # include an artificially high scoring discovery to encourage promotion
        "force_discoveries": [
            {"path": ["b1","b2"], "confidence": 0.95, "reason": "test-high-confidence"}
        ]
    }

    # Ensure auto-gen is enabled for tests via env toggle
    monkeypatch.setenv('INCIDENT_AUTOGEN_ENABLED','1')
    monkeypatch.setenv('INCIDENT_AUTOGEN_PATH_THRESHOLD','0.8')

    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200
    j = r.json()

    # Check that session summary reports auto_generated_incidents
    assert 'auto_generated_incidents' in j
    ag = j['auto_generated_incidents']
    assert isinstance(ag, list)
    assert len(ag) >= 1

    # Check aggregator actually received an incident
    incidents = GLOBAL_INCIDENTS.list_incidents()
    assert len(incidents) >= 1
    found = any('test-high-confidence' in (inc.get('summary') or '') or 'test-session-auto-1' in (inc.get('session_id') or '') for inc in incidents)
    assert found
