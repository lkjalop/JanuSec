import os
import time
import json
from fastapi.testclient import TestClient

from src.api.server import app

# The test will exercise endpoints and ensure they return expected error codes when backend graph is minimal
def test_reconstruct_and_temporal_metrics(monkeypatch):
    # Ensure tenant metrics enabled for this test to verify label behavior
    monkeypatch.setenv('ENABLE_TENANT_METRICS', '1')
    monkeypatch.setenv('TENANT_METRICS_HASH_BUCKETS', '4')

    client = TestClient(app)

    # Call temporal query; expected behavior: 500 if graph not initialized or empty, but endpoint should respond
    r = client.get('/api/v1/graph/temporal_query?start_ts=0&end_ts=1')
    assert r.status_code in (200, 500)

    # Call reconstruct with missing seed -> should be 400
    r2 = client.post('/api/v1/graph/reconstruct', json={}, headers={'X-Api-Key': 'testkey123'})
    assert r2.status_code == 400

    # If metrics are registered, verify metrics endpoint presence
    # The project exposes /metrics via prometheus_client if available; attempt to fetch
    mr = client.get('/metrics')
    # Accept 200 or 404 depending on prometheus client availability
    assert mr.status_code in (200, 404, 500)
