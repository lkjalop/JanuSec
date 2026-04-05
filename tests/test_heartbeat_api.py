from fastapi.testclient import TestClient
from src.api.app import app
import shutil, os


def setup_function(fn):
    if os.path.exists('data'):
        shutil.rmtree('data')


def test_ingest_and_baseline_and_anomalies():
    client = TestClient(app)
    tenant = 't_http'
    src = 'svc_a'

    # ingest a few events to create a baseline (simulate past buckets by directly calling record_ingest is fine, but use API here for simplicity)
    resp = client.post('/api/v1/heartbeat/ingest', json={'tenant_id': tenant, 'source': src, 'count': 10})
    assert resp.status_code == 200

    # read baseline (should be available, may be small)
    resp = client.get(f'/api/v1/heartbeat/baseline/{tenant}/{src}')
    assert resp.status_code == 200
    body = resp.json()
    assert body.get('tenant_id') == tenant

    # query anomalies - must pass sources as repeatable query param
    resp = client.get(f'/api/v1/heartbeat/anomalies/{tenant}?sources={src}')
    assert resp.status_code == 200
    # returns a mapping (possibly empty)
    assert isinstance(resp.json(), dict)
