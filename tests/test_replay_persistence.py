import os, json, time, shutil, tempfile
from fastapi.testclient import TestClient
# Import server within a function to avoid heavy collection-time import

def get_app():
    from src.api.app import create_app
    # Ensure replay routers are registered by importing server lazily
    import src.api.server  # noqa: F401
    return create_app({'mode': 'test'})

# Ensure test runs in lite mode to avoid heavy startup side-effects
os.environ.setdefault('PLATFORM_LITE_INIT','1')

def test_replay_session_persists_tenant(tmp_path):
    # Point tenant persist dir to a temp location
    tdir = tmp_path / 'tenants'
    os.environ['TENANT_PERSIST_DIR'] = str(tdir)
    client = TestClient(get_app())
    tenant = 'tenant-replay-test'
    resp = client.post('/api/v1/replay/diff', json={'tenant': tenant, 'steps': 2, 'no_bg': True})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    sid = data['session_id']
    assert data.get('tenant') == tenant
    # Wait briefly for worker to finish (steps=2, 0.05s each)
    time.sleep(0.3)
    # Check meta.json includes tenant
    meta_path = os.path.join(os.getcwd(), 'data', 'replays', sid, 'meta.json')
    assert os.path.exists(meta_path)
    with open(meta_path, 'r', encoding='utf-8') as fh:
        meta = json.load(fh)
    assert meta.get('tenant') == tenant
    # Check tenant directory persisted
    part_path = tdir / tenant / 'partition.json'
    assert part_path.exists(), f"Expected tenant partition at {part_path}"


def test_replay_worker_idempotent(tmp_path):
    os.environ['TENANT_PERSIST_DIR'] = str(tmp_path / 'tenants2')
    client = TestClient(get_app())
    tenant = 'tenant-replay-idem'
    r1 = client.post('/api/v1/replay/diff', json={'tenant': tenant, 'steps': 1, 'no_bg': True})
    assert r1.status_code == 200
    sid = r1.json()['session_id']
    meta_path = os.path.join(os.getcwd(), 'data', 'replays', sid, 'meta.json')
    # Force completion deterministically by invoking worker (idempotent)
    from src.api.replay_endpoints import _run_reprocess
    import asyncio
    asyncio.run(_run_reprocess(sid, {'tenant': tenant, 'steps': 1, 'force': True}))
    with open(meta_path, 'r', encoding='utf-8') as fh:
        meta1 = json.load(fh)
    assert meta1.get('status') == 'completed'
    # Trigger second start for same session id by invoking worker directly (simulate) -> should no-op
    asyncio.run(_run_reprocess(sid, {'tenant': tenant, 'steps': 3, 'force': True}))
    with open(meta_path, 'r', encoding='utf-8') as fh:
        meta2 = json.load(fh)
    # Should remain completed and not reflect new steps
    assert meta2.get('status') == 'completed'
    assert meta2.get('progress') == 100
