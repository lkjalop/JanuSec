from fastapi.testclient import TestClient
import src.api.app as appmod

class MockHG:
    def __init__(self):
        self.edges = []
        self.nodes = {}
    def add_edge(self, src, dst, etype, **kwargs):
        self.edges.append((src,dst,etype,kwargs))
    def add_node_attr(self, node, **attrs):
        self.nodes.setdefault(node,{}).update(attrs)


def test_csv_upload_for_remote_access():
    client = TestClient(appmod.app)
    mock = MockHG()
    appmod.app.GLOBAL_HOPGRAPH = mock
    # Read sample CSV
    with open('tests/data/sample_remote_access.csv','rb') as f:
        files = {'file': ('sample_remote_access.csv', f, 'text/csv')}
        # Set header to use in-process TestClient forwarding
        r = client.post('/api/v1/csv_multi/upload', files=files, headers={'x-test-inproc': '1'})
    assert r.status_code == 200
    j = r.json()
    # forwarded count should be >= 1
    assert j['session'].get('forwarded', 0) >= 1
    # The forwarding should have triggered the remote_access ingest which adds edges
    assert len(mock.edges) >= 1
