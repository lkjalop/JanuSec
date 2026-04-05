from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})


client = TestClient(app)


def test_qualys_config_status_sync_basic():
    hdr = {'x-api-key': 'devkey123'}
    cfg = {'enabled': True, 'api_url': 'https://qualys.example', 'username': 'u', 'password': 'p'}
    r = client.post('/api/v1/integrations/qualys/config', json=cfg, headers=hdr)
    assert r.status_code == 200
    st = client.get('/api/v1/integrations/qualys/status', headers=hdr)
    assert st.status_code == 200
    js = st.json()
    assert js.get('enabled') is True
    sy = client.post('/api/v1/integrations/qualys/sync', headers=hdr)
    assert sy.status_code == 200


def test_tenable_config_status_sync_basic():
    hdr = {'x-api-key': 'devkey123'}
    cfg = {'enabled': True, 'api_url': 'https://tenable.example', 'access_key': 'a', 'secret_key': 'b'}
    r = client.post('/api/v1/integrations/tenable/config', json=cfg, headers=hdr)
    assert r.status_code == 200
    st = client.get('/api/v1/integrations/tenable/status', headers=hdr)
    assert st.status_code == 200
    js = st.json()
    assert js.get('enabled') is True
    sy = client.post('/api/v1/integrations/tenable/sync', headers=hdr)
    assert sy.status_code == 200

