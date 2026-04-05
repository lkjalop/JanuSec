import json
from fastapi.testclient import TestClient
from src.api import app as appmod


def test_mapping_changes_kind_and_forwards():
    client = TestClient(appmod.app)
    # set a mock hopgraph if the app supports it in tests
    try:
        from tests.mock_hopgraph import MockHG
        appmod.app.GLOBAL_HOPGRAPH = MockHG()
    except Exception:
        pass

    # CSV headers are non-canonical: client_ip, username, target
    csv_bytes = b"client_ip,username,target,port,proto\n9.9.9.9,eve,hostx,22,ssh\n"
    mapping = json.dumps({'src_ip': 'client_ip', 'user': 'username', 'dest_host': 'target', 'protocol': 'proto'})

    r = client.post('/api/v1/csv_multi/upload', files={'file': ('mapped.csv', csv_bytes, 'text/csv')}, data={'mapping': mapping}, headers={'x-test-inproc': '1'})
    assert r.status_code == 200
    j = r.json()
    assert j['session']['mapping'] != 'auto'
    assert j['session']['kind'] in ('remote_access', 'email', 'unknown')
    assert j['session']['forwarded'] >= 1
