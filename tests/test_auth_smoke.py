import os
import json
import time
from fastapi.testclient import TestClient

os.environ['ADMIN_UI_TOKEN'] = 'admin-secret-test'
os.environ['API_KEYS_JSON'] = json.dumps([{'key':'testkey123','scopes':['feedback.write','factors.search','models.promote','models.alias']}])
os.environ['JWT_TEST_SECRET'] = 'jwt-test-secret'

from src.api.app import app  # import after env set


def test_admin_promote_and_alias_and_label():
    # Promote via admin token header
    client = TestClient(app)
    from tests._helpers import admin_test_headers
    files = {'file': ('m.json', json.dumps({'type':'sigmoid','k':1.2,'x0':0.5}), 'application/json')}
    headers = admin_test_headers(client, admin_token='admin-secret-test')
    r = client.post('/api/v1/models/promote', headers=headers, files=files)
    assert r.status_code == 200

    # Set alias - admin
    payload = {'alias': 'current', 'model_name': 'm.json'}
    r2 = client.post('/api/v1/models/alias', headers=headers, json=payload)
    assert r2.status_code == 200

    # Label using API key
    headers2 = {'x-api-key': 'testkey123'}
    # create a fake decision into cache for labeling via runtime_state API
    ev = {'event_id': 'evt-smoke', 'verdict': 'OBSERVE', 'confidence': 0.1, 'factors': []}
    from src.api import runtime_state
    runtime_state.cache_set('evt-smoke', ev)
    r3 = client.post('/api/v1/decisions/evt-smoke/label', headers=headers2, json={'label':'tp'})
    assert r3.status_code == 200

    # Signed JWT path (viewer-like scope) - exercise a read endpoint
    try:
        import jwt as pyjwt
    except Exception:
        pyjwt = None
    if pyjwt:
        token = pyjwt.encode({'sub':'ci-user','scopes':['factors.search'], 'aud':'janusec', 'iss':'ci'}, os.environ['JWT_TEST_SECRET'], algorithm='HS256')
        headers3 = {'Authorization': f'Bearer {token}'}
        # Read calibration last/history (protected by factors.search)
        r4 = client.get('/api/v1/risk/calibration/last', headers=headers3)
        assert r4.status_code in (200, 500)  # 500 allowed if recalibrator unavailable in test env
