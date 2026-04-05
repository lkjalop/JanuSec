import os
import tempfile
from src.api.subscription_store import SubscriptionStore


def test_subscription_store_save_get_delete():
    tmpdir = tempfile.mkdtemp(prefix='substoretest')
    dbpath = os.path.join(tmpdir, 'subs.db')
    store = SubscriptionStore(db_path=dbpath)

    sid = 'test-sub-1'
    tenant = 'tenant-abc'
    provider = 'msgraph'
    payload = {'id': sid, 'tenant': tenant, 'resource': 'me/mailFolders/inbox/messages'}

    store.save(sid, tenant, provider, payload, expires_at='12345', created_at='11111')

    got = store.get(sid)
    assert got is not None
    assert got['id'] == sid
    assert got['tenant_id'] == tenant or got.get('tenant') == tenant

    lst = store.list_for_tenant(tenant)
    assert any(x['id'] == sid for x in lst)

    all_items = store.all()
    assert any(x['id'] == sid for x in all_items)

    store.delete(sid)
    assert store.get(sid) is None
