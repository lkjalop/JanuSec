import time
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.incidents.aggregator import GLOBAL_INCIDENTS
from src.api import runtime_state


def test_auto_generated_incident_created(monkeypatch):
    app = create_app()
    client = TestClient(app)

    # ensure aggregator is clean
    try:
        GLOBAL_INCIDENTS.incidents.clear()
    except Exception:
        try:
            GLOBAL_INCIDENTS.__dict__.get('incidents', {}).clear()
        except Exception:
            pass

    # Build a minimal payload that should trigger auto-gen logic
    # Use session_ids referencing synthetic fixtures and inject a synthetic high-confidence path discovery
    payload = {
        "session_ids": ["batch-overlap-A","batch-overlap-B"],
        "correlate": True,
        "ewma": False,
        "test_discoveries": [
            {"type": "path", "signals": ["b1__b2"], "confidence": 0.95, "rationale": ["test-high-confidence"], "session_id": '__USE_CURRENT__'}
        ]
    }

    # Ensure auto-gen is enabled for tests via env toggle
    monkeypatch.setenv('INCIDENT_AUTOGEN_ENABLED','1')
    monkeypatch.setenv('INCIDENT_AUTOGEN_PATH_THRESHOLD','0.8')

    r = client.post('/api/v1/graph/session/build', json=payload)
    assert r.status_code == 200
    j = r.json()

    # Check that session summary reports auto_generated_incidents
    assert 'summary' in j
    summary = j['summary']
    # Accept either legacy UI-style evidence or the new auto_generated_incidents list
    assert ('auto_generated_incidents' in summary) or ('auto_incident_evidence' in summary)
    if 'auto_generated_incidents' in summary:
        ag = summary['auto_generated_incidents']
        assert isinstance(ag, list)
        assert len(ag) >= 1
    else:
        ev = summary.get('auto_incident_evidence')
        assert ev is not None

    # Check aggregator actually received an incident
    incidents = GLOBAL_INCIDENTS.list_incidents()
    assert len(incidents) >= 1
    found = any('path_high_confidence' in (e.get('factors') or []) or any('test-high-confidence' in (ev.get('rationale') or []) for ev in (inc.get('ingested_events_full') or [])) for inc in incidents for e in inc.get('events', []))
    assert found
