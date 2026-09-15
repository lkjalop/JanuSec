import pytest
from fastapi.testclient import TestClient


class MockHG:
    def __init__(self):
        self.edges = []
        self.nodes = {}
    def add_edge(self, src, dst, etype, **kwargs):
        self.edges.append((src,dst,etype,kwargs))
    def add_node_attr(self, node, **attrs):
        self.nodes.setdefault(node,{}).update(attrs)


def test_remote_access_ingest_roundtrip():
    import src.api.app as appmod
    client = TestClient(appmod.app)
    # attach mock hopgraph before making requests
    mock = MockHG()
    appmod.app.GLOBAL_HOPGRAPH = mock

    payload = {
        'src_ip': '8.8.8.8',
        'user': 'bob',
        'dest_host': 'host-a',
        'dest_port': 3389,
        'protocol': 'rdp',
        'timestamp': 't1',
    }
    r = client.post('/api/v1/remote_access/ingest', json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data.get('status') == 'accepted'
    # ensure mock hopgraph recorded at least one edge
    assert len(mock.edges) >= 1
