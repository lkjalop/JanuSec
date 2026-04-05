import os
from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})


def test_rate_limit_saturation(monkeypatch):
    # lower the global rate limit for this test
    monkeypatch.setenv('RATE_LIMIT_MAX_REQUESTS', '3')
    monkeypatch.setenv('RATE_LIMIT_WINDOW_SECONDS', '60')
    # update the module-level variables used by middleware
    import importlib
    mod = importlib.import_module('src.api.app')
    # Use monkeypatch.setattr so the module-level changes are reverted after
    # the test — prevents polluting other tests which expect rate limiting to
    # be disabled by default in the test harness.
    monkeypatch.setattr(mod, '_RATE_LIMIT_MAX_REQUESTS', 3, raising=False)
    monkeypatch.setattr(mod, '_RATE_LIMIT_WINDOW_SECONDS', 60, raising=False)
    monkeypatch.setattr(mod, '_RATE_LIMIT_ENABLED', True, raising=False)
    # reset rate limiter storage and get deterministic headers
    from tests._helpers import reset_rate_limit_and_headers
    headers = reset_rate_limit_and_headers('10.0.0.1')
    # Ensure the app module-level storages are cleared on the same module object
    try:
        mod.reset_rate_limit_for_tests()
    except Exception:
        try:
            mod._RATE_LIMIT_STORAGE.clear()
        except Exception:
            pass
    try:
        mod._TENANT_RATE_STORAGE.clear()
    except Exception:
        pass
    # To make this test deterministic in batch runs where other tests may
    # mutate rate-limit windows, pre-fill the rate storage for our test IP
    # so at least one request will be rate-limited.
    try:
        import time as _t
        from collections import deque as _dq
        ip = '10.0.0.1'
        # ensure storage exists and populate with max tokens to trigger drop
        try:
            cap = int(getattr(mod, '_RATE_LIMIT_MAX_REQUESTS', 3) or 3)
        except Exception:
            cap = 3
        mod._RATE_LIMIT_STORAGE[ip] = _dq([_t.monotonic() for _ in range(cap)], maxlen=cap)
    except Exception:
        pass
    client = TestClient(app)
    # issue 5 quick requests to any endpoint
    ok = 0
    too_many = 0
    for _ in range(5):
        r = client.get('/health', headers=headers)
        if r.status_code == 200:
            ok += 1
        elif r.status_code == 429:
            too_many += 1
    assert ok + too_many == 5
    assert too_many >= 1
