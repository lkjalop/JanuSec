import os, json
import pytest
from fastapi.testclient import TestClient

# Ensure API key enforcement relaxed for test
os.environ.setdefault('STRICT_API_KEY_ENFORCEMENT','0')

from src.api.app import app  # noqa

client = TestClient(app)

@pytest.mark.timeout(10)
def test_graph_session_explain_confidence_breakdown():
    # Build a session with synthetic overlap batches
    payload = {
        "session_ids": ["batch-overlap-alpha","batch-overlap-beta"],
        "correlate": True,
        "ewma": False
    }
    r = client.post('/api/v1/graph/session/build', json=payload, headers={'x-api-key':'devkey123'})
    assert r.status_code == 200, r.text
    data = r.json()
    sid = data['session_id']
    # Fetch explain
    er = client.get(f'/api/v1/graph/session/{sid}/explain', headers={'x-api-key':'devkey123'})
    assert er.status_code == 200, er.text
    exp = er.json()
    # Assertions: breakdown present and contains final
    breakdown = exp.get('confidence_breakdown')
    assert isinstance(breakdown, dict) and 'final' in breakdown and breakdown['final'] <= 1.0
    # Narrative is non-empty string
    assert isinstance(exp.get('narrative'), str) and len(exp['narrative']) > 10
    # Key factors exclude batch_missing
    kf = exp.get('key_factors') or []
    assert all(k != 'batch_missing' for k in kf)
    # Hotspots exist (overlap expected for synthetic overlap batches)
    hs = exp.get('overlap_hotspots') or []
    assert isinstance(hs, list)
    # For synthetic overlap pairs we expect at least one hotspot
    assert len(hs) >= 1

