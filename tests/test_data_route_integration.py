from fastapi.testclient import TestClient
from src.api.app import create_app
import json


class StubHG:
    def __init__(self):
        self.nodes = {}
        self.edges = []
    def add_node_attr(self, nid, **kwargs):
        self.nodes.setdefault(nid, {}).update(kwargs)
    def add_edge(self, src, dst, etype, source=None, attrs=None):
        self.edges.append({'src': src, 'dst': dst, 'type': etype, 'source': source, 'attrs': attrs})


def test_data_route_large_export_triggers_detector(monkeypatch):
    app = create_app()
    # Inject a stub GLOBAL_HOPGRAPH into app
    stub = StubHG()
    app.GLOBAL_HOPGRAPH = stub
    client = TestClient(app)
    payload = {
        'user': 'eve',
        'database': 'customers',
        'table': 'payments',
        'record_count': 20000,
        'sink': 's3://exfil/bucket/key',
    }
    resp = client.post('/api/v1/data/ingest', json=payload)
    assert resp.status_code == 200
    # Check that the hopgraph stub saw nodes/edges
    assert any(k.startswith('user:') for k in stub.nodes.keys())
    # Large export should create or touch user node and possibly factors via detector
    assert 'user:eve' in stub.nodes
