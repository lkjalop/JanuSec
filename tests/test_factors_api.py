import json
from src.api.app import app
from fastapi.testclient import TestClient


def test_get_factors_list():
    client = TestClient(app)
    r = client.get('/api/v1/factors', headers={'x-api-key': 'devkey123'})
    assert r.status_code == 200
    j = r.json()
    assert 'domains' in j
    assert 'factors' in j
    assert isinstance(j['factors'], list)
    # Basic sanity: mapping_semantics should be present
    ids = [f.get('id') for f in j['factors']]
    assert 'mapping_semantics' in ids
