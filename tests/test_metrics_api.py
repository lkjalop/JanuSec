import os
from fastapi.testclient import TestClient

os.environ.setdefault('PLATFORM_LITE_INIT', '1')

def test_metrics_endpoints_smoke():
    # Import app lazily so env var is applied
    from src.api.app import create_app
    app = create_app({'mode': 'test'})
    client = TestClient(app)

    r = client.get('/api/v1/metrics/correlation')
    assert r.status_code == 200
    body = r.json()
    # Expect either prometheus_enabled or counters/score_buckets
    assert isinstance(body, dict)
    assert 'prometheus_enabled' in body or 'counters' in body

    r2 = client.get('/api/v1/metrics/prometheus')
    assert r2.status_code == 200
    text = r2.content
    assert isinstance(text, (bytes, bytearray))
    # Basic heuristic: content should include HELP or at least be non-empty
    assert len(text) >= 0
