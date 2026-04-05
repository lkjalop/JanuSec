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


def test_email_csv_upload_and_mapping():
    client = TestClient(appmod.app)
    mock = MockHG()
    appmod.app.GLOBAL_HOPGRAPH = mock
    with open('tests/data/sample_email_bec.csv','rb') as f:
        files = {'file': ('sample_email_bec.csv', f, 'text/csv')}
        r = client.post('/api/v1/csv_multi/upload', files=files, headers={'x-test-inproc': '1'})
    assert r.status_code == 200
    j = r.json()
    assert j['session']['kind'] == 'email'
    assert j['session']['forwarded'] >= 1


def test_email_direct_ingest_adds_bec_and_url_factors():
    client = TestClient(appmod.app)
    mock = MockHG()
    appmod.app.GLOBAL_HOPGRAPH = mock
    payload = {
        'from': 'ceo@paypa2.com',  # non-ascii domain triggers homograph
        'to': 'finance@example.com',
        'subject': 'Urgent wire transfer needed',
        'raw': {
            'body': 'Please complete payment: https://bit.ly/xyz'
        }
    }
    r = client.post('/api/v1/email/ingest', json=payload)
    assert r.status_code == 200
    # Validate factors present in edge meta
    assert any(
        ('attrs' in kwargs and isinstance(kwargs.get('attrs'), dict) and any(
            f in kwargs['attrs'].get('factors', []) for f in (
                'email:homograph_suspect','email:bec_language','email:suspicious_url'
            )
        ))
        for (_s,_d,_t,kwargs) in mock.edges
    )
