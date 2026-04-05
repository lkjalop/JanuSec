from fastapi.testclient import TestClient
from src.api.server import app, DECISION_CACHE
from src.api.runtime_state import drain_event_queue_for_tests

client = TestClient(app)


def test_decision_cache_population_and_drain():
    # Ensure clean state
    DECISION_CACHE.clear()
    evt = {'id': 'test-evt-1', 'host': 'h1', 'proc_name': 'cmd.exe'}
    # Post event to log_batch endpoint which should enqueue and classify
    resp = client.post('/api/v1/endpoints/log_batch', json={'events': [evt], 'classify': True, 'send_alerts': False})
    assert resp.status_code == 200
    # Drain queued events to force ingestion/hopgraph processing
    drained = drain_event_queue_for_tests()
    # Allow some small time for any background work
    # Now assert decision cache contains decision for our event id (best-effort)
    # Some pipelines may use event id or event_id key in decision entries
    found = False
    for k in list(DECISION_CACHE.keys()):
        if 'test-evt-1' in str(k) or 'test-evt-1' in str(DECISION_CACHE.get(k)):
            found = True
            break
    assert found, f"Decision for event 'test-evt-1' not found in DECISION_CACHE after drain (drained={drained})"
