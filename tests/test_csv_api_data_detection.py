from fastapi.testclient import TestClient
import src.api.app as appmod


def _post_csv(client: TestClient, path: str):
    with open(path, 'rb') as f:
        files = {'file': (path.split('/')[-1], f, 'text/csv')}
        return client.post('/api/v1/csv_multi/upload', files=files, headers={'x-test-inproc': '1'})


def test_api_gateway_detection_and_forward():
    client = TestClient(appmod.app)
    r = _post_csv(client, 'tests/fixtures/api_gateway_sample.csv')
    assert r.status_code == 200
    j = r.json()
    assert j['session']['kind'].startswith('api_')
    assert j['session']['forwarded'] >= 1


def test_database_detection_and_forward():
    client = TestClient(appmod.app)
    r = _post_csv(client, 'tests/fixtures/database_query_sample.csv')
    assert r.status_code == 200
    j = r.json()
    assert j['session']['kind'] == 'data_access'
    assert j['session']['forwarded'] >= 1

