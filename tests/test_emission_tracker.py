import time
from fastapi.testclient import TestClient

from src.api.app import app
from src.graph.hopgraph import GLOBAL_HOPGRAPH

client = TestClient(app)

def test_emitted_factor_recording():
    # Ensure process + domain nodes and factor attribution triggers emission
    proc = 'process:testproc:1234'
    dom = 'domain:example.com'
    GLOBAL_HOPGRAPH.add_node_attr(proc, type='process', name='testproc')
    GLOBAL_HOPGRAPH.add_node_attr(dom, type='domain', name='example.com')
    # Add an edge to simulate contact then attribute factor
    GLOBAL_HOPGRAPH.add_edge(proc, dom, 'contacts_domain')
    GLOBAL_HOPGRAPH.add_node_factor(proc, 'endpoint:unsigned_exec')
    # Query emitted factors
    resp = client.get('/api/v1/factors/emitted')
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data['count'] >= 1
    factors = [e['factor'] for e in data['entries']]
    assert 'endpoint:unsigned_exec' in factors
    # Since parameter filter
    since = time.time() - 60
    resp2 = client.get(f'/api/v1/factors/emitted?since={since}')
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert 'endpoint:unsigned_exec' in [e['factor'] for e in data2['entries']]
