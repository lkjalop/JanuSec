import os
import json
from fastapi.testclient import TestClient
from src.api.server import app

client = TestClient(app)
from tests._helpers import admin_test_headers


def test_promote_and_alias(tmp_path, monkeypatch):
    # ensure ADMIN_UI_TOKEN is set for token-based admin auth
    os.environ['ADMIN_UI_TOKEN'] = 'admintoken'
    # create a dummy model file
    model = tmp_path / 'm.json'
    model.write_text(json.dumps({'type':'sigmoid','k':2.0,'x0':0.5}))
    with open(model, 'rb') as fh:
        files = {'file': ('m.json', fh, 'application/json')}
        hdrs = admin_test_headers(client, admin_token='admintoken')
        resp = client.post('/api/v1/models/promote', files=files, headers=hdrs)
    assert resp.status_code == 200
    j = resp.json()
    assert 'registry' in j
    # set alias via API
    payload = {'alias':'current','model_name': j['registry'].get('models',[{}])[-1].get('name')}
    resp2 = client.post('/api/v1/models/alias', json=payload, headers=hdrs)
    assert resp2.status_code == 200
    j2 = resp2.json()
    assert j2.get('ok') is True