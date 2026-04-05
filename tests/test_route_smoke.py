import os
from typing import Set

from fastapi.testclient import TestClient


def test_route_smoke_root_metrics_and_kev_status(monkeypatch):
    # Prefer the console frontend during this test so "/" serves static LIVE console
    monkeypatch.setenv('DEFAULT_FRONTEND', 'console')
    # Ensure metrics registry initializes in test mode if prometheus_client is unavailable
    # (harmless if prometheus_client is present)
    monkeypatch.setenv('METRICS_TEST_MODE', '1')

    # Import app after env so it picks up DEFAULT_FRONTEND for static serving
    from src.api.app import create_app
    app = create_app({'mode': 'test'})  # type: ignore

    client = TestClient(app)

    # Root should serve HTML (LIVE console or React shim)
    r_root = client.get('/')
    assert r_root.status_code == 200
    ct = r_root.headers.get('content-type', '')
    assert 'text/html' in ct or 'text/plain' in ct

    # Metrics may be available or deliberately unavailable; accept 200 or 503
    r_metrics = client.get('/metrics')
    assert r_metrics.status_code in (200, 503)
    if r_metrics.status_code == 200:
        assert 'text/plain' in (r_metrics.headers.get('content-type') or '')

    # KEV status may be 200 (when enricher wired) or 503 (unavailable in CI)
    r_kev = client.get('/api/v1/compliance/kev/status', headers={'x-api-key': 'devkey123'})
    assert r_kev.status_code in (200, 503)

    # Crossmap should always return JSON 200
    r_x = client.get('/api/v1/compliance/crossmap', headers={'x-api-key': 'devkey123'})
    assert r_x.status_code == 200
    j = r_x.json()
    assert 'frameworks' in j and 'crossmap' in j

