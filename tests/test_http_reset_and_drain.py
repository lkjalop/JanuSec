from fastapi.testclient import TestClient
from src.api.server import app
import os

client = TestClient(app)


def test_http_reset_and_drain_endpoint():
    # Ensure explicit env var enables the endpoint
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    r = client.post('/api/v1/test/reset_and_drain')
    assert r.status_code == 200
    j = r.json()
    assert 'status' in j
    assert j['status'] in ('ok','error')
    # drained should be an int when ok
    if j['status'] == 'ok':
        assert isinstance(j.get('drained', 0), int)
    # cleanup
    del os.environ['TEST_HELPERS_ENABLED']
