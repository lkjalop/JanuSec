from fastapi.testclient import TestClient
import src.api.app as appmod


def _post_csv(client: TestClient, path: str):
    with open(path, 'rb') as f:
        files = {'file': (path.split('/')[-1], f, 'text/csv')}
        return client.post('/api/v1/csv_multi/upload', files=files, headers={'x-test-inproc': '1'})


def test_vpn_detection_and_forward():
    client = TestClient(appmod.app)
    r = _post_csv(client, 'tests/fixtures/vpn_access_sample.csv')
    assert r.status_code == 200
    j = r.json()
    assert j['session']['kind'] == 'remote_access'
    assert j['session']['forwarded'] >= 1


def test_rdp_detection_and_forward():
    client = TestClient(appmod.app)
    r = _post_csv(client, 'tests/fixtures/rdp_sessions_sample.csv')
    assert r.status_code == 200
    j = r.json()
    assert j['session']['kind'] == 'remote_access'
    assert j['session']['forwarded'] >= 1

