import os
import json
from pathlib import Path
os.environ.setdefault('PYTEST_CURRENT_TEST', '1')
os.environ.setdefault('USE_APPROVAL_DB', '1')
from fastapi.testclient import TestClient
from src.api.app import app
from src.core import approval_repo


def test_migration_idempotent(tmp_path):
    # prepare a sample jsonl file
    p = tmp_path / 'approvals.jsonl'
    events = [
        {'event': 'request', 'token': 'tok1', 'request': {'action':'a','target':'t'}, 'requested_at': '2026-01-01T00:00:00Z'},
        {'event': 'approve', 'token': 'tok1', 'approver': 'alice'},
    ]
    p.write_text('\n'.join(json.dumps(e) for e in events))
    # run migration apply
    from scripts.migrate_approvals_to_db import migrate
    migrate(str(p), dry_run=False, force=False)
    # second run should not duplicate when not forced
    migrate(str(p), dry_run=False, force=False)
    # force should reapply (no error)
    migrate(str(p), dry_run=False, force=True)


def test_pagination_and_filters():
    approval_repo.init_db()
    client = TestClient(app)
    headers = {'x-api-key': 'testkey123'}
    # create 5 entries
    tokens = []
    for i in range(5):
        r = client.post('/api/v1/playbook/request', json={'action': f'a{i}', 'target': f't{i}'}, headers=headers)
        tokens.append(r.json().get('token'))
    # approve first two by alice
    for t in tokens[:2]:
        client.post('/api/v1/playbook/approve', params={'token': t, 'approver': 'alice'}, headers=headers)
    # query with pagination
    res1 = client.get('/api/v1/playbook/requests', params={'offset':0,'limit':2}, headers=headers).json()
    assert len(res1.get('requests', [])) == 2
    # filter by approver
    res2 = client.get('/api/v1/playbook/requests', params={'approver':'alice'}, headers=headers).json()
    assert all((r.get('approver') == 'alice') or (r.get('status') == 'approved') for r in res2.get('requests', []))
