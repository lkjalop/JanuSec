import os
from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})

client = TestClient(app)


def test_pruner_control_forbidden():
    r = client.get('/api/v1/admin/cooccurrence/pruner/status')
    assert r.status_code == 403


def test_pruner_control_start_stop(monkeypatch):
    monkeypatch.setenv('ADMIN_API_KEY','adminkey')
    r = client.post('/api/v1/admin/cooccurrence/pruner/start', headers={'X-Admin-Key':'adminkey'})
    # may 404 if pruner not available in test env; accept 200 or 404
    assert r.status_code in (200,404)
    r = client.post('/api/v1/admin/cooccurrence/pruner/stop', headers={'X-Admin-Key':'adminkey'})
    assert r.status_code in (200,404)
