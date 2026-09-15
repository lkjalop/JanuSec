from fastapi.testclient import TestClient
import src.api.app as appmod
import json


class MockHG:
    def __init__(self):
        self.edges = []
        self.nodes = {}
    def add_edge(self, src, dst, etype, **kwargs):
        self.edges.append((src,dst,etype,kwargs))
    def add_node_attr(self, node, **attrs):
        self.nodes.setdefault(node,{}).update(attrs)


def test_mapping_variation_applied():
    client = TestClient(appmod.app)
    mock = MockHG()
    appmod.app.GLOBAL_HOPGRAPH = mock
    # create a CSV with non-canonical headers
    csv_bytes = b"client_ip,username,target,port,proto\n9.9.9.9,eve,hostx,22,ssh\n"
    files = {'file': ('mapped.csv', ('dummy', csv_bytes, 'text/csv'))}
    mapping = json.dumps({'src_ip': 'client_ip', 'user': 'username', 'dest_host': 'target', 'protocol': 'proto'})
    r = client.post('/api/v1/csv_multi/upload', files={'file': ('mapped.csv', csv_bytes, 'text/csv')}, data={'mapping': mapping}, headers={'x-test-inproc': '1'})
    assert r.status_code == 200
    j = r.json()
    assert j['session']['mapping'] != 'auto'
    assert j['session']['forwarded'] >= 1


def test_forward_failure_summary(monkeypatch):
    client = TestClient(appmod.app)
    # monkeypatch async_forward_rows to simulate failure
    import src.api.csv_multi_endpoints as cme
    async def fake_async(rows, kind, base_url='http://localhost:8080'):
        return {'forwarded': 0, 'failed': len(rows), 'errors': ['downstream_error']}
    monkeypatch.setattr(cme, 'async_forward_rows', fake_async)
    csv_bytes = b"src_ip,user,dest_host\n1.1.1.1,joe,hostz\n"
    r = client.post('/api/v1/csv_multi/upload', files={'file': ('f.csv', csv_bytes, 'text/csv')})
    assert r.status_code == 200
    j = r.json()
    assert j['session']['failed'] >= 1
