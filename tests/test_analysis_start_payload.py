from fastapi.testclient import TestClient
from src.api.app import app


def test_start_session_payload():
    client = TestClient(app)
    sid = 'regress-session-1'
    headers = {'x-api-key': 'devkey123'}
    r = client.post('/api/v1/analysis/session/start', json={'session_id': sid, 'payload': {'x': 'y'}}, headers=headers)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get('session_id') == sid
    # check status endpoint
    rs = client.get(f'/api/v1/analysis/session/{sid}/status')
    assert rs.status_code in (200, 404)
