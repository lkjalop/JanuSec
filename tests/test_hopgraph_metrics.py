from fastapi.testclient import TestClient
from src.api.app import app
from graph.hopgraph import GLOBAL_HOPGRAPH
from metrics import hopgraph_metrics

def test_hopgraph_metrics_increment():
    client = TestClient(app)
    from tests._helpers import default_test_headers
    hdrs = default_test_headers()
    hopgraph_metrics.init()
    GLOBAL_HOPGRAPH.add_edge('host:m','process:p','runs')
    GLOBAL_HOPGRAPH.add_edge('process:p','domain:ex.org','contacts_domain')
    # Trigger metrics init via explain
    r = client.get('/api/v1/graph/explain', params={'node':'host:m'}, headers=hdrs)
    assert r.status_code == 200
    # Another explain to increment again (cache may bypass if not different; use depth variation)
    r2 = client.get('/api/v1/graph/explain', params={'node':'host:m','depth':5}, headers=hdrs)
    assert r2.status_code == 200
    m = client.get('/metrics', headers=hdrs)
    assert m.status_code == 200
    body = m.text
    assert 'hopgraph_edges_total' in body
    assert 'hopgraph_explain_requests_total' in body