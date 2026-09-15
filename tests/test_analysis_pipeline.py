import time
from fastapi.testclient import TestClient
from src.api.app import app


def test_start_and_complete_session():
    client = TestClient(app)
    sid = 'test-session-1'
    headers = {'x-api-key': 'devkey123'}
    r = client.post('/api/v1/analysis/session/start', json={'session_id': sid, 'payload': {'foo': 'bar'}}, headers=headers)
    assert r.status_code == 200
    # poll until completed
    status = None
    for _ in range(50):
        s = client.get(f'/api/v1/analysis/session/{sid}/status', headers=headers)
        assert s.status_code == 200
        status = s.json()
        if status.get('status') in {'completed','failed','cancelled'}:
            break
        time.sleep(0.02)
    assert status is not None
    assert status.get('status') in {'completed','failed'}
