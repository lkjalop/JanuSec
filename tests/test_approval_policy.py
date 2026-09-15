import os
import tempfile
import importlib
from src.core import approval_repo


def test_n_of_m_policy(tmp_path, monkeypatch):
    # Use a temp DB path
    dbp = str(tmp_path / 'approvals.db')
    monkeypatch.setenv('APPROVAL_DB_PATH', dbp)
    monkeypatch.setenv('USE_APPROVAL_DB', '1')
    # reload approval_store so it picks up USE_APPROVAL_DB at import-time
    import src.core.approval_store as approval_store
    importlib.reload(approval_store)
    # ensure repo uses the same db path
    approval_repo.init_db()

    # create policy: require 2 approvals for action 'isolate'
    approval_repo.save_policy('isolate_policy', 'isolate', 2, 3, scope={'reason': 'high_severity'}, enabled=True)

    # create a request with action 'isolate'
    token = 'tok-test-nm'
    approval_store.create_request(token, {'action': 'isolate', 'target': 'host-1'})

    # initially not approved
    assert not approval_store.is_approved(token)

    # first approval
    approval_store.approve_token(token, 'alice')
    assert not approval_store.is_approved(token)

    # second approval
    approval_store.approve_token(token, 'bob')
    assert approval_store.is_approved(token)
