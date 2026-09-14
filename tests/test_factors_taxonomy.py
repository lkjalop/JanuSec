from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)

def test_taxonomy_basic():
    r = client.get('/api/v1/factors/taxonomy')
    assert r.status_code == 200, r.text
    j = r.json()
    assert 'factors' in j and isinstance(j['factors'], list)
    assert len(j['factors']) >= 50
    domains = {f['domain'] for f in j['factors'] if 'domain' in f}
    assert len(domains) >= 8
    # Check precedence ordering property exists
    sample = j['factors'][0]
    assert 'precedence' in sample


def test_factor_history_endpoint_empty():
    r = client.get('/api/v1/factors/history/unknown_factor_xyz')
    assert r.status_code == 200, r.text
    j = r.json()
    assert j['factor'] == 'unknown_factor_xyz'
    assert isinstance(j['history'], list)
