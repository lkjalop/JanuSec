import os
os.environ.setdefault('PYTEST_CURRENT_TEST', '1')
os.environ.setdefault('USE_APPROVAL_DB', '1')
from fastapi.testclient import TestClient
from src.api.app import app
from src.core import approval_repo


def setup_module():
    # ensure DB is initialized clean
    approval_repo.init_db()


def test_listing_and_export():
    client = TestClient(app)
    headers = {'x-api-key': 'testkey123'}
    # create two requests
    r1 = client.post('/api/v1/playbook/request', json={'action':'a1','target':'t1'}, headers=headers)
    t1 = r1.json().get('token')
    r2 = client.post('/api/v1/playbook/request', json={'action':'a2','target':'t2'}, headers=headers)
    t2 = r2.json().get('token')
    # approve t1
    client.post('/api/v1/playbook/approve', params={'token': t1, 'approver': 'alice'}, headers=headers)
    # list all
    lst = client.get('/api/v1/playbook/requests', headers=headers).json()
    assert 'requests' in lst
    # export json
    exp = client.get('/api/v1/playbook/requests/export', params={'format':'json'}, headers=headers)
    assert exp.status_code == 200
    # export csv
    csvr = client.get('/api/v1/playbook/requests/export', params={'format':'csv'}, headers=headers)
    assert csvr.status_code == 200
    assert 'token' in csvr.text
