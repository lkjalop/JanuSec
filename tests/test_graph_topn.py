from fastapi.testclient import TestClient
from src.api.app import app
from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH as G
from tests._helpers import default_test_headers

client = TestClient(app)


def setup_module():
    # seed some edges
    G.add_edge('user:alice','host:host1','lateral_login',0.6)
    G.add_edge('user:alice','role:admin','priv_escalation',0.9)
    G.add_edge('role:admin','cloud_resource:prod-db','cloud_pivot',0.8)


def test_topn_identity():
    hdrs = default_test_headers()
    r = client.get('/api/v1/graph/topn?graph=identity&topn=3', headers=hdrs)
    assert r.status_code == 200, r.text
    data = r.json()
    assert 'topn' in data and isinstance(data['topn'], list)
    assert len(data['topn']) <= 3
