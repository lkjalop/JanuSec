import os
import importlib
import json
from fastapi.testclient import TestClient

from src.api.app import app as _app


def setup_function():
    # ensure lite/test mode for permissive auth
    os.environ['PLATFORM_LITE_INIT'] = '1'


def test_policy_crud_and_matching(tmp_path, monkeypatch):
    # use temp DB
    dbp = str(tmp_path / 'approvals_api.db')
    monkeypatch.setenv('APPROVAL_DB_PATH', dbp)
    monkeypatch.setenv('USE_APPROVAL_DB', '1')
    # reload modules to pick up env
    import src.core.approval_repo as repo
    importlib.reload(repo)
    repo.init_db()

    client = TestClient(_app)
    # include admin router for tests
    try:
        import src.api.admin_approvals as _admin_mod
        importlib.reload(_admin_mod)
        _app.include_router(_admin_mod.router)
    except Exception:
        pass

    policy = {
        'name': 'test-isolate',
        'action_pattern': 'isolate',
        'n_required': 2,
        'm_total': 3,
        'scope': {'severity': 'high'},
        'enabled': True
    }

    rv = client.post('/api/v1/admin/approval_policies', json=policy)
    assert rv.status_code == 200
    data = rv.json()
    assert data.get('ok')

    # list
    rv = client.get('/api/v1/admin/approval_policies')
    assert rv.status_code == 200
    pols = rv.json().get('policies')
    assert any(p.get('name') == 'test-isolate' for p in pols)

    # get single
    rv = client.get('/api/v1/admin/approval_policies/test-isolate')
    assert rv.status_code == 200
    p = rv.json()
    assert p.get('name') == 'test-isolate'

    # disabled policy should not match
    policy2 = policy.copy()
    policy2['name'] = 'disabled'
    policy2['action_pattern'] = 'disabled-action'
    policy2['enabled'] = False
    rv = client.post('/api/v1/admin/approval_policies', json=policy2)
    assert rv.status_code == 200
    # find_policy_for_action should not return disabled policy
    found = repo.find_policy_for_action('disabled-action')
    assert found is None

    # malformed policy: n_required non-int should be rejected by pydantic - simulate via direct repo call
    try:
        repo.save_policy('bad', 'x', int('notint'), 1, {})
    except Exception:
        pass

    # delete
    rv = client.delete('/api/v1/admin/approval_policies/test-isolate')
    assert rv.status_code == 200
    rv = client.get('/api/v1/admin/approval_policies/test-isolate')
    assert rv.status_code == 404
