from __future__ import annotations

import os
from fastapi.testclient import TestClient


def _client():
    os.environ['PLATFORM_LITE_INIT'] = '1'
    from src.api.app import app
    return TestClient(app)


def test_seed_decisions_and_recent_list():
    client = _client()
    # Seed 3 deterministic decisions
    payload = {'count': 3, 'prefix': 'seed-test', 'tenant_id': 'demo'}
    r = client.post('/api/v1/dev/seed_decisions', json=payload, headers={'x-api-key': 'devkey123'})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get('count') == 3
    seeded = data.get('seeded') or []
    assert len(seeded) == 3

    # Query recent decisions fallback (in-memory) and assert seeded ids present
    r2 = client.get('/api/v1/decisions/recent?limit=10', headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'demo'})
    assert r2.status_code == 200, r2.text
    rows = r2.json().get('decisions') or []
    ids = {r.get('event_id') or r.get('id') for r in rows}
    for sid in seeded:
        assert sid in ids, f'seeded id {sid} not found in recent decisions: {ids}'


def test_recent_decisions_available_without_platform_lite(monkeypatch):
    """Ensure helper functions exist when only TEST_HELPERS_ENABLED toggled."""
    import importlib
    import src.api.app as app_module

    monkeypatch.delenv('PLATFORM_LITE_INIT', raising=False)
    monkeypatch.setenv('TEST_HELPERS_ENABLED', '1')

    reloaded = importlib.reload(app_module)
    client = TestClient(reloaded.app)
    try:
        if hasattr(reloaded, 'DECISION_CACHE') and hasattr(reloaded.DECISION_CACHE, 'clear'):
            try:
                reloaded.DECISION_CACHE.clear()
            except Exception:
                pass
        reloaded.DECISION_CACHE['evt-lite'] = {
            'event_id': 'evt-lite',
            'tenant_id': 'demo',
            'verdict': 'OBSERVE',
            'confidence': 0.5,
            'factors': [],
            'timestamp': 1234567890,
        }
        resp = client.get('/api/v1/decisions/recent', headers={'x-api-key': 'devkey123', 'X-Tenant-ID': 'demo'})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert any(dec.get('event_id') == 'evt-lite' for dec in body.get('decisions', []))
    finally:
        client.close()
        # Restore module to default lite-enabled state for other tests
        monkeypatch.setenv('PLATFORM_LITE_INIT', '1')
        importlib.reload(app_module)
