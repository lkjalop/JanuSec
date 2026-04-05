from fastapi.testclient import TestClient
from src.api.app import create_app


def test_llm_costs_endpoint_exposes_trackers():
    app = create_app()
    client = TestClient(app)
    resp = client.get('/api/v1/metrics/llm_costs')
    assert resp.status_code == 200
    data = resp.json()
    assert 'external' in data and 'local' in data
    assert 'total_calls' in data['external']
    assert 'total_calls' in data['local']
