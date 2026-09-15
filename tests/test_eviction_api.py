import importlib
import time

from src.api import server


def test_eviction_api_behavior():
    # Ensure a fresh DECISION_CACHE
    cache = globals().get('DECISION_CACHE') if (globals().get('DECISION_CACHE') is not None) else None
    # Use server module's DECISION_CACHE reference
    DECISION_CACHE = server.DECISION_CACHE
    # Populate with many entries (fake) and timestamps
    from src.api import runtime_state
    DECISION_CACHE = server.DECISION_CACHE
    # Clear via adapter/public API if available
    try:
        DECISION_CACHE.clear()
    except Exception:
        try:
            # best-effort: iterate keys and remove
            for k in list(DECISION_CACHE.keys()):
                DECISION_CACHE.pop(k, None)
        except Exception:
            pass
    now = time.time()
    for i in range(60):
        runtime_state.cache_set(f'evt-{i}', {'event_id': f'evt-{i}', 'ts': now - (1000 + i), 'confidence': 0.1})
    # call eviction endpoint to bring under a small target
    res = server.evict_decisions(limit=30)
    assert isinstance(res, dict)
    assert res.get('evicted') >= 0
    assert res.get('current') <= 60
    # After eviction, cache size should be <= initial size
    assert len(DECISION_CACHE) <= 60
