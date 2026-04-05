from fastapi.testclient import TestClient
from src.api.app import app

def test_labeling_list_and_ui():
    client = TestClient(app)
    r = client.get('/api/v1/labeling/list')
    assert r.status_code == 200
    j = r.json()
    assert 'ok' in j
    r2 = client.get('/api/v1/labeling/ui')
    assert r2.status_code == 200
    assert '<h3>Upload labels CSV' in r2.text
