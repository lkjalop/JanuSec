import os
import json
import pytest

from fastapi.testclient import TestClient

from src.api.app import app


@pytest.fixture(autouse=True)
def enable_test_helpers(monkeypatch, tmp_path):
    # enable test helpers and persist dir
    monkeypatch.setenv('TEST_HELPERS_ENABLED', '1')
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(tmp_path))
    yield


def test_decision_create_approve_execute_rollback():
    client = TestClient(app)
    # Create a decision
    payload = {
        'decision_type': 'contain',
        'persona': 'soc_analyst',
        'urgency': 'normal',
        'question': 'Block suspicious IP?',
        'context': 'Detected high triage traffic from 1.2.3.4',
        'options': [{'label': 'Block', 'id': 'block'}, {'label': 'Ignore', 'id': 'ignore'}]
    }
    r = client.post('/api/v1/decision/create', json=payload, headers={'x-actor': 'testuser'})
    assert r.status_code == 200
    body = r.json()
    gate_id = body.get('gate_id')
    assert gate_id

    # Approve the decision
    r2 = client.post('/api/v1/decision/approve', json={'gate_id': gate_id, 'approved_option': 'block'}, headers={'x-actor': 'approver'})
    assert r2.status_code == 200
    assert r2.json().get('status') in ('approved', 'pending_second_approval')

    # Execute the decision
    r3 = client.post('/api/v1/decision/execute', json={'gate_id': gate_id, 'action_payload': {'ip': '1.2.3.4'}}, headers={'x-actor': 'operator'})
    assert r3.status_code == 200
    jr = r3.json()
    assert jr.get('status') == 'executed'

    # Rollback
    r4 = client.post('/api/v1/decision/rollback', json={'gate_id': gate_id, 'reason': 'false positive'}, headers={'x-actor': 'approver'})
    assert r4.status_code == 200
    assert r4.json().get('status') == 'rolled_back'
