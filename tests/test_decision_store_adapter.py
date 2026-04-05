import time
import pytest

from src.api import runtime_state
from src.api.decision_store import DecisionStore


def test_lru_cache_basic_ops():
    if not hasattr(runtime_state, '_LRUCache'):
        pytest.skip('LRU cache implementation not exposed in this runtime (DecisionStore enabled)')
    cache = runtime_state._LRUCache(maxsize=3)
    cache['a'] = 1
    cache['b'] = 2
    cache['c'] = 3
    assert len(cache) == 3
    assert cache.get('a') == 1
    cache['d'] = 4
    assert len(cache) == 3
    assert 'a' not in cache
    assert list(cache.keys()) == list(cache._order.keys())


def test_decision_store_add_get_remove_clear():
    store = DecisionStore(max_items=10)
    store.add('k1', {'ts': time.time(), 'foo': 'bar'})
    assert store.get('k1')['foo'] == 'bar'
    # remove
    val = store.remove('k1')
    assert val is not None
    assert store.get('k1') is None
    # add multiple
    store.add('k2', {'ts': time.time(), 'v': 2})
    store.add('k3', {'ts': time.time(), 'v': 3})
    assert len(store) == 2
    store.clear()
    assert len(store) == 0


def test_decision_store_evict_n():
    store = DecisionStore(max_items=100)
    for i in range(5):
        store.add(f'k{i}', {'ts': time.time() + i, 'i': i})
    ev = store.evict_n(2)
    assert ev == 2
    assert len(store) == 3


def test_adapter_against_store():
    store = DecisionStore(max_items=100)
    adapter = runtime_state._DecisionCacheAdapter(store)
    adapter['one'] = {'ts': time.time(), 'n': 1}
    assert 'one' in adapter
    assert adapter.get('one')['n'] == 1
    adapter['two'] = {'ts': time.time(), 'n': 2}
    assert len(adapter) == 2
    popped = adapter.pop('one')
    assert popped is not None
    assert 'one' not in adapter
    adapter.clear()
    assert len(adapter) == 0


@pytest.mark.parametrize('store_enabled', [True, False])
def test_cache_set_normalization(monkeypatch, store_enabled):
    # Ensure cache_set attempts to coerce dict to DecisionRecord when schema exists
    # We'll just exercise the code path; behavior differs depending on runtime
    monkeypatch.setenv('DECISION_STORE_ENABLED', '1' if store_enabled else '0')
    # import runtime_state fresh to pick up env (simple reload pattern)
    import importlib
    import src.api.runtime_state as rs
    importlib.reload(rs)
    # Use cache_set to write a dict
    rs.cache_set('x1', {'event_id': 'x1', 'verdict': 'OBSERVE', 'confidence': 0.0})
    val = rs.cache_get('x1')
    # It should exist
    assert val is not None