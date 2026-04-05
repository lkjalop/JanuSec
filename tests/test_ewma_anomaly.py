import time
import sys
from types import ModuleType

import pytest


def test_ewma_update_converges():
    # import inside test so module state is fresh
    import src.api.integrations_endpoints as ie

    # Reset internal state
    ie._ERR_EWMA.clear()

    key = 'webhook:http://example.test'
    values = [1.0, 1.0, 0.0, 1.0]
    prev = 0.0
    alpha = ie._EWMA_ALPHA
    for v in values:
        expected = (1 - alpha) * prev + alpha * v
        got = ie._ewma_update(key, v)
        # floating tolerance
        assert abs(got - expected) < 1e-8
        # reflect state for next iteration
        prev = expected


def test_ewma_threshold_and_cooldown(monkeypatch):
    import src.api.integrations_endpoints as ie

    # ensure empty state
    ie._ERR_EWMA.clear()
    ie._EWMA_LAST_ALERT.clear()

    # Insert a fake decisions_stream module so _maybe_emit_webhook_anomaly can import it
    mod_name = 'src.api.decisions_stream'
    called = []
    m = ModuleType(mod_name)

    async def publish_decision(summary):
        called.append(summary)

    m.publish_decision = publish_decision
    sys.modules[mod_name] = m

    # Ensure asyncio.create_task executes immediately in this test so the
    # publish_decision coroutine runs synchronously and appends into `called`.
    import asyncio as _asyncio
    def _run_now(coro):
        try:
            return _asyncio.run(coro)
        except Exception:
            # fall back to ensure no-op
            return None
    monkeypatch.setattr(_asyncio, 'create_task', _run_now)

    # Lower thresholds for test speed
    monkeypatch.setattr(ie, '_EWMA_THRESH', 0.2)
    monkeypatch.setattr(ie, '_EWMA_COOLDOWN', 2)

    url = 'https://svc.test'
    key = f'webhook:{url}'
    # Build EWMA above threshold by applying error=1 several times
    for _ in range(5):
        ie._ewma_update(key, 1.0)

    # Now call maybe_emit - should result in a publish_decision call
    ie._maybe_emit_webhook_anomaly(url)
    assert len(called) == 1

    # Calling again immediately should not create another due to cooldown
    ie._maybe_emit_webhook_anomaly(url)
    assert len(called) == 1

    # Simulate cooldown expiry by setting last alert sufficiently far in the past
    now = time.time()
    ie._EWMA_LAST_ALERT[f'webhook:{url}'] = now - 10
    ie._maybe_emit_webhook_anomaly(url)
    assert len(called) >= 2
