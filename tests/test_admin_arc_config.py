import os
from fastapi.testclient import TestClient

from src.api.app import create_app, app
from src.api import admin_arc


def _ensure_admin_arc():
    # include router idempotently for test environment
    try:
        app.include_router(admin_arc.router)
    except Exception:
        pass


def test_get_default_arc_config():
    # Ensure test mode so app startup doesn't run heavy tasks
    os.environ['FAST_TEST_MODE'] = '1'
    _ensure_admin_arc()
    client = TestClient(app)

    resp = client.get('/api/v1/admin/arc/config')
    assert resp.status_code == 200
    data = resp.json()
    assert 'mode' in data and data['mode'] in {'off', 'sample', 'on'}
    assert 'sample_rate' in data
    # default sample rate should be numeric and between 0 and 1
    assert isinstance(data['sample_rate'], (int, float))
    assert 0.0 <= float(data['sample_rate']) <= 1.0


def test_set_arc_config_and_get():
    os.environ['FAST_TEST_MODE'] = '1'
    _ensure_admin_arc()
    client = TestClient(app)

    payload = {'mode': 'on', 'sample_rate': 0.5}
    resp = client.post('/api/v1/admin/arc/config', json=payload)
    assert resp.status_code == 200
    j = resp.json()
    assert j.get('ok') is True
    # subsequent GET reflects change
    resp2 = client.get('/api/v1/admin/arc/config')
    assert resp2.status_code == 200
    data = resp2.json()
    assert data['mode'] == 'on'
    assert abs(float(data['sample_rate']) - 0.5) < 1e-6
