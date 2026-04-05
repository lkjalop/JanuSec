import os
from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})

client = TestClient(app)


def test_suppression_admin_forbidden():
    r = client.get('/api/v1/admin/suppression/')
    assert r.status_code == 403


def test_suppression_admin_set_requires_key(monkeypatch):
    monkeypatch.setenv('ADMIN_API_KEY','secret123')
    r = client.post('/api/v1/admin/suppression/set', json={"a,b": -0.01})
    assert r.status_code == 403
    r = client.post('/api/v1/admin/suppression/set', headers={'X-Admin-Key':'secret123'}, json={"a,b": -0.01})
    assert r.status_code == 200
