from fastapi.testclient import TestClient
from fastapi import FastAPI
from src.api.playbook_approval_endpoints import router as approval_router
import os, shutil

# Ensure pytest-friendly auth fallbacks are active during tests
os.environ.setdefault('PYTEST_CURRENT_TEST', '1')


def setup_function(fn):
    # clear approval store
    d = 'data'
    if os.path.exists(d):
        shutil.rmtree(d)
    # mark pytest context for auth fallbacks
    os.environ['PYTEST_CURRENT_TEST'] = '1'


def test_request_approve_execute_flow():
    import os
    os.environ['PYTEST_CURRENT_TEST'] = '1'
    from src.api.app import app as full_app
    client = TestClient(full_app)
    headers = {'x-api-key': 'testkey123'}
    # request a playbook
    resp = client.post('/api/v1/playbook/request', json={'action': 'restart_collector', 'target': 'demo_collector'}, headers=headers)
    assert resp.status_code == 200
    token = resp.json().get('token')
    assert token

    # initially cannot execute without approval
    exec_resp = client.post('/api/v1/playbook/execute', json={'action': 'restart_collector', 'target': 'demo_collector', 'approval_token': token, 'dry_run': True}, headers=headers)
    # because approval isn't recorded yet, server should reject (403)
    assert exec_resp.status_code == 403

    # approve it (explicit approver param)
    appr = client.post('/api/v1/playbook/approve', params={'token': token, 'approver': 'tester'}, headers=headers)
    assert appr.status_code == 200

    # check audit/requests list for approver recorded
    lst = client.get('/api/v1/playbook/requests', headers=headers)
    assert lst.status_code == 200
    items = lst.json().get('requests')
    assert isinstance(items, list)
    found = [i for i in items if i.get('token') == token]
    assert found, 'token should appear in requests list'
    req = found[0]
    assert req.get('status') == 'approved'
    assert req.get('approver') == 'tester'

    # now execute should succeed (dry_run)
    exec_resp2 = client.post('/api/v1/playbook/execute', json={'action': 'restart_collector', 'target': 'demo_collector', 'approval_token': token, 'dry_run': True}, headers=headers)
    assert exec_resp2.status_code == 200
    j = exec_resp2.json()
    assert j.get('ok') is True
    assert j.get('result', {}).get('status') == 'dry_run'


def test_revoke_flow():
    # Ensure test-mode env is set before creating TestClient
    os.environ.setdefault('PYTEST_CURRENT_TEST', '1')
    from src.api.app import app as full_app
    client = TestClient(full_app)
    headers = {'x-api-key': 'testkey123'}
    # request & approve
    r = client.post('/api/v1/playbook/request', json={'action': 'restart_collector', 'target': 'demo_collector'}, headers=headers)
    token = r.json().get('token')
    assert token
    client.post('/api/v1/playbook/approve', params={'token': token, 'approver': 'tester'}, headers=headers)
    # revoke
    rv = client.post('/api/v1/playbook/revoke', params={'token': token, 'reason': 'no longer needed'}, headers=headers)
    assert rv.status_code == 200
    assert rv.json().get('status') == 'revoked'
    # list should show revoked status
    lst = client.get('/api/v1/playbook/requests', headers=headers)
    items = lst.json().get('requests')
    found = [i for i in items if i.get('token') == token]
    assert found and found[0].get('status') == 'revoked'
