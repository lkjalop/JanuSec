import pytest
from fastapi.testclient import TestClient
from src.api.main import app
import os


client = TestClient(app)


def test_precision_daily_insert_and_get():
    payload = {
        'day': '2025-01-01',
        'tenant_id': 'test-tenant',
        'tp': 5,
        'fp': 2,
        'fn': 1
    }
    r = client.post('/api/v1/metrics/precision/daily', json=payload)
    assert r.status_code == 200 and r.json().get('ok')

    r2 = client.get('/api/v1/metrics/precision/daily', params={'tenant_id': 'test-tenant', 'start': '2025-01-01', 'end': '2025-01-02'})
    assert r2.status_code == 200
    data = r2.json()
    assert data.get('ok') and isinstance(data.get('rows'), list)


def test_shadow_enable_disable():
    r = client.post('/api/v1/ab_test/enable', json={'test_id': 'shadow-1', 'name': 'shadow test', 'rollout_pct': 20})
    assert r.status_code == 200 and r.json().get('ok')
    r2 = client.post('/api/v1/ab_test/disable', json={'test_id': 'shadow-1'})
    assert r2.status_code == 200 and r2.json().get('ok')
