from __future__ import annotations
from fastapi.testclient import TestClient
from src.api.app import create_app, app


def test_metrics_labeling_endpoint_smoke():
    # create app in test mode
    client = TestClient(app)
    resp = client.get('/api/v1/metrics/labeling')
    assert resp.status_code == 200
    data = resp.json()
    assert data.get('ok') is True
