from fastapi.testclient import TestClient
import os

def test_http_drain_event_queue_enabled():
    # Enable test helpers via env var
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    from src.api.server import app
    client = TestClient(app)
    resp = client.post('/api/v1/test/drain_event_queue')
    assert resp.status_code == 200
    j = resp.json()
    assert j['status'] == 'ok'
    assert isinstance(j['drained'], int)
    # When queue is empty initial drain should be zero
    assert j['drained'] == 0
    # Clean up env var
    del os.environ['TEST_HELPERS_ENABLED']

def test_http_drain_event_queue_disabled():
    # Ensure the helper flag is absent
    os.environ.pop('TEST_HELPERS_ENABLED', None)
    from src.api.server import app
    client = TestClient(app)
    resp = client.post('/api/v1/test/drain_event_queue')
    assert resp.status_code == 404
    j = resp.json()
    assert j.get('detail') == 'not_available'
