from fastapi.testclient import TestClient
from src.api.app import app


def test_graph_self_check_basic():
    client = TestClient(app)
    r = client.get('/api/v1/graph/self_check')
    assert r.status_code == 200
    j = r.json()
    # basic keys present
    assert 'nodes' in j
    assert 'edges' in j
    assert 'wal_tail' in j
    assert 'snapshot_path' in j
