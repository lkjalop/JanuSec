import os
import time
import shutil
from src.core.tenant_store import persist_tenant_partition, load_tenant_partition, prune_inactive_tenants, tenant_path, DATA_DIR


def test_persist_and_load(tmp_path, monkeypatch):
    # point tenant data dir to tmp
    monkeypatch.setenv('TENANT_PERSIST_DIR', str(tmp_path))
    # reload module to pick up env var change
    import importlib
    import src.core.tenant_store as ts
    importlib.reload(ts)

    tenant = 'test-tenant'
    payload = {'foo': 'bar'}
    ok = ts.persist_tenant_partition(tenant, payload)
    assert ok
    loaded = ts.load_tenant_partition(tenant)
    assert loaded is not None
    assert loaded.get('foo') == 'bar'
    assert '_persisted_ts' in loaded


def test_prune_inactive_tenants(tmp_path, monkeypatch):
    monkeypatch.setenv('TENANT_PERSIST_DIR', str(tmp_path))
    import importlib
    import src.core.tenant_store as ts
    importlib.reload(ts)

    tenant = 'to-prune'
    payload = {'k': 'v'}
    assert ts.persist_tenant_partition(tenant, payload)
    # simulate old timestamp by editing file
    p = os.path.join(ts.tenant_path(tenant), 'partition.json')
    with open(p, 'r') as fh:
        import json
        data = json.load(fh)
    data['_persisted_ts'] = time.time() - 3600 * 24 * 7
    with open(p, 'w') as fh:
        json.dump(data, fh)

    # prune using small TTL
    pruned = ts.prune_inactive_tenants(ttl_seconds=1)
    assert pruned >= 1
    # ensure directory removed
    assert not os.path.isdir(ts.tenant_path(tenant))
