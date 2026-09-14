import os
from fastapi.testclient import TestClient

# Lazy import to avoid heavy app creation during collection
def get_app():
    from src.api.app import create_app
    return create_app({'mode': 'test'})


def test_metrics_summary_endpoint():
    client = TestClient(get_app())
    r = client.get('/api/v1/metrics/summary')
    assert r.status_code == 200
    j = r.json()
    assert isinstance(j, dict)
    # values should be dicts with numeric fields when present
    for k,v in j.items():
        assert isinstance(k, str)
        assert isinstance(v, dict)
        # optional fields
        assert 'dedupe' in v or 'upserts_success' in v or 'upserts_failed' in v