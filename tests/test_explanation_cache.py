import time
import os
from src.core.cache.explanation_cache import ExplanationCache


def test_explanation_cache_set_get(tmp_path, monkeypatch):
    d = tmp_path / 'cache'
    cache = ExplanationCache(persist_dir=str(d))
    key = 'incident:abc123'
    payload = {'factors': [{'factor': 'test', 'score': 0.5}], 'other': 1}
    cache.set(key, payload, ttl=5, meta={'gen': 'unit'})
    got = cache.get(key)
    assert got is not None
    assert got.get('payload') == payload
    assert got.get('meta', {}).get('gen') == 'unit'


def test_explanation_cache_expiry(tmp_path):
    d = tmp_path / 'cache'
    cache = ExplanationCache(persist_dir=str(d))
    key = 'incident:exp'
    payload = {'factors': []}
    cache.set(key, payload, ttl=1)
    got = cache.get(key)
    assert got is not None
    time.sleep(1.2)
    expired = cache.get(key)
    assert expired is None
