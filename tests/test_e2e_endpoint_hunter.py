import time

from fastapi.testclient import TestClient

from src.api.server import app
from src.api import runtime_state

client = TestClient(app)

def _wait_decision(event_id: str, timeout: float = 3.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            v = runtime_state.cache_get(event_id)
            if v is not None:
                return v
        except Exception:
            try:
                if event_id in runtime_state.DECISION_CACHE:
                    return runtime_state.DECISION_CACHE[event_id]
            except Exception:
                pass
        time.sleep(0.05)
    return None

def test_endpoint_hunter_rare_lineage_and_stabilization():
    event_id = 'e2e-rare-1'
    payload = {
        'id': event_id,
        'event_type': 'process_start',
        'details': {
            'process': {
                'name': 'rundll32.exe',
                'parent_name': 'wscript.exe'
            }
        }
    }
    r = client.post('/api/v1/events', json=payload)
    assert r.status_code == 200, r.text
    rec = _wait_decision(event_id)
    assert rec is not None, 'decision not materialized'
    # First sighting should include rare lineage factor (auto-attached in pipeline result)
    assert any(f.startswith('endpoint:rare_lineage') for f in rec.factors), rec.factors

    # Re-submit the same parent->child multiple times to exceed rare_cutoff
    for i in range(6):
        payload['id'] = f'e2e-rare-repeat-{i}'
        r = client.post('/api/v1/events', json=payload)
        assert r.status_code == 200
        _wait_decision(payload['id'])

    # New event after stabilization should no longer have rare lineage
    final_id = 'e2e-rare-final'
    payload['id'] = final_id
    r = client.post('/api/v1/events', json=payload)
    assert r.status_code == 200
    final_rec = _wait_decision(final_id)
    assert final_rec is not None
    assert not any(f.startswith('endpoint:rare_lineage') for f in final_rec.factors), final_rec.factors

def test_endpoint_hunter_benign_process_pair():
    event_id = 'e2e-benign-1'
    payload = {
        'id': event_id,
        'event_type': 'process_start',
        'details': {
            'process': {
                'name': 'notepad.exe',
                'parent_name': 'explorer.exe'
            }
        }
    }
    r = client.post('/api/v1/events', json=payload)
    assert r.status_code == 200
    rec = _wait_decision(event_id)
    assert rec is not None
    # Expect no endpoint factors for common benign pair
    assert not any(f.startswith('endpoint:') for f in rec.factors), rec.factors
