import os
from fastapi.testclient import TestClient

from src.api.app import create_app
app = create_app({'mode': 'test'})


def test_suppression_admin_requires_key():
    # ensure no ADMIN_API_KEY set
    os.environ.pop('ADMIN_API_KEY', None)
    client = TestClient(app)
    r = client.get('/api/v1/admin/suppression/')
    assert r.status_code == 403


def test_suppression_admin_accepts_key():
    os.environ['ADMIN_API_KEY'] = 'adminkey123'
    client = TestClient(app)
    r = client.get('/api/v1/admin/suppression/', headers={'x-admin-key': 'adminkey123'})
    assert r.status_code == 200
