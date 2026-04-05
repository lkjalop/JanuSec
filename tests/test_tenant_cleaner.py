import time
import importlib
from threading import Event


def test_tenant_cleaner_runs(monkeypatch):
    calls = {'count': 0}
    def fake_prune(ttl=None):
        calls['count'] += 1
        return 0
    monkeypatch.setattr('src.core.tenant_store.prune_inactive_tenants', fake_prune)
    # reload cleaner to pick up patched function
    import src.core.tenant_cleaner as tc
    importlib.reload(tc)
    # start with small interval
    tc.start_tenant_cleaner(interval_seconds=1)
    try:
        # wait up to 2.5s for a couple loops
        time.sleep(2.5)
    finally:
        tc.stop_tenant_cleaner()
    assert calls['count'] >= 1
