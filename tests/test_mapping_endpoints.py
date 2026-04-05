import os, json
from fastapi.testclient import TestClient
from src.api.app import create_app

client = TestClient(create_app({'mode':'test'}))

def test_mapping_crud(tmp_path, monkeypatch):
    # ensure mappings dir is isolated
    d = tmp_path / 'maps'
    monkeypatch.setenv('MAPPINGS_DIR', str(d))
    app = create_app({'mode':'test'})
    cl = TestClient(app)
    # list empty
    r = cl.get('/api/v1/mappings/')
    assert r.status_code == 200
    assert 'mappings' in r.json()
    # save mapping
    payload = {'fields': {'ip': 'dst_ip', 'country': 'geo.dst_ip.country'}}
    r2 = cl.post('/api/v1/mappings/testmap', json=payload)
    assert r2.status_code == 200
    # get mapping
    r3 = cl.get('/api/v1/mappings/testmap')
    assert r3.status_code == 200 and r3.json().get('fields')
    # delete mapping
    r4 = cl.delete('/api/v1/mappings/testmap')
    assert r4.status_code == 200
