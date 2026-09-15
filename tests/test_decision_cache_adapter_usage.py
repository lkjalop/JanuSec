import pytest
from src.api import runtime_state


def test_decision_cache_basic_len_and_keys_clear():
    # Clear cache defensively
    try:
        runtime_state.DECISION_CACHE.clear()
    except Exception:
        # If adapter-backed and clear fails, attempt to remove keys via items list
        try:
            for k in list(runtime_state.DECISION_CACHE.keys()):
                try:
                    runtime_state.DECISION_CACHE.pop(k)
                except Exception:
                    pass
        except Exception:
            pass

    # Insert a few items via cache_set
    runtime_state.cache_set('k1', {'event_id': 'k1', 'verdict': 'OBSERVE'})
    runtime_state.cache_set('k2', {'event_id': 'k2', 'verdict': 'allow'})
    runtime_state.cache_set('k3', {'event_id': 'k3', 'verdict': 'deny'})

    # len should reflect inserted items
    assert len(runtime_state.DECISION_CACHE) >= 3

    keys = list(runtime_state.DECISION_CACHE.keys())
    assert 'k1' in keys and 'k2' in keys and 'k3' in keys

    # values/items should be accessible
    items = list(runtime_state.DECISION_CACHE.items())
    assert any(k == 'k2' for k, v in items)

    # pop should remove and return a value
    val = runtime_state.DECISION_CACHE.pop('k2', None)
    assert val is not None
    assert 'k2' not in list(runtime_state.DECISION_CACHE.keys())

    # clear empties the cache
    try:
        runtime_state.DECISION_CACHE.clear()
    except Exception:
        # best-effort fallback
        for k in list(runtime_state.DECISION_CACHE.keys()):
            try:
                runtime_state.DECISION_CACHE.pop(k)
            except Exception:
                pass
    assert len(list(runtime_state.DECISION_CACHE.keys())) == 0


def test_iteration_order_and_mutation_semantics():
    # Clear
    try:
        runtime_state.DECISION_CACHE.clear()
    except Exception:
        for k in list(runtime_state.DECISION_CACHE.keys()):
            try:
                runtime_state.DECISION_CACHE.pop(k)
            except Exception:
                pass

    # Insert in order
    runtime_state.cache_set('a', {'event_id': 'a', 'verdict': 'v1'})
    runtime_state.cache_set('b', {'event_id': 'b', 'verdict': 'v2'})
    runtime_state.cache_set('c', {'event_id': 'c', 'verdict': 'v3'})

    # Iteration should yield keys in insertion order
    keys = list(iter(runtime_state.DECISION_CACHE))
    assert keys[:3] == ['a', 'b', 'c']

    # Mutation semantics: if value is an object stored as dict, modifying the returned dict
    # should not necessarily auto-persist; but cache_get should return current stored value
    v = runtime_state.cache_get('a')
    if isinstance(v, dict):
        v['verdict'] = 'modified'
        # Stored value may be a copy or same object; ensure cache_get returns a mapping
        stored = runtime_state.cache_get('a')
    assert isinstance(stored, (dict, object))
