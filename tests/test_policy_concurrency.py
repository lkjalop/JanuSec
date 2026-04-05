import os
import importlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.core import approval_repo


def test_concurrent_approvals(tmp_path, monkeypatch):
    dbp = str(tmp_path / 'approvals_conc.db')
    monkeypatch.setenv('APPROVAL_DB_PATH', dbp)
    monkeypatch.setenv('USE_APPROVAL_DB', '1')
    import src.core.approval_repo as repo
    importlib.reload(repo)
    repo.init_db()

    # create policy requiring 3 approvals from pool of 5
    pool = ['a1','a2','a3','a4','a5']
    repo.save_policy('concurrent', 'concurrent_action', 3, 5, approver_pool=pool, scope={'desc':'concurrency test'})

    # create request
    from src.core import approval_store
    importlib.reload(approval_store)
    token = 'tok-conc'
    approval_store.create_request(token, {'action':'concurrent_action','target':'host-x'})

    # make concurrent approvals from the pool
    def do_approve(a):
        try:
            approval_store.approve_token(token, a)
            return True
        except Exception:
            return False

    approved = False
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(do_approve, a) for a in pool]
        for f in as_completed(futures):
            f.result()
    # after concurrent approvals, is_approved should be True (3 of 5)
    assert approval_store.is_approved(token)
