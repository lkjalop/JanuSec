import time

import pytest

try:
    import fakeredis
except Exception:
    fakeredis = None

from core.correlation.redis_cache import InMemoryTemporalCache, RedisTemporalCache


@pytest.mark.skipif(fakeredis is None, reason="fakeredis not installed")
def test_redis_temporal_record_and_seen_within():
    r = fakeredis.FakeRedis()
    url = None
    # construct RedisTemporalCache but monkeypatch its redis client
    cache = RedisTemporalCache(redis_url='redis://localhost')
    cache.redis = r

    cache.record('host1', ['f1','f2'], window_seconds=2)
    assert cache.seen_within('host1','f1', 5) is True
    assert cache.seen_within('host1','f2', 5) is True
    assert cache.host_count() >= 1

    # Wait for expiry
    time.sleep(2.1)
    assert cache.seen_within('host1','f1', 1) is False

@pytest.mark.skipif(fakeredis is None, reason="fakeredis not installed")
def test_cleanup_hosts_removes_stale_entries():
    r = fakeredis.FakeRedis()
    cache = RedisTemporalCache(redis_url='redis://localhost')
    cache.redis = r

    cache.record('hA', ['x'], window_seconds=1)
    cache.record('hB', ['y'], window_seconds=1)
    assert cache.host_count() >= 2

    # delete host key directly to simulate expiry
    r.delete('janusec:correlation:host:hA')
    removed = cache.cleanup_hosts(max_scan=10)
    # should remove at least the deleted host
    assert removed >= 1

def test_inmemory_temporal_cache_behavior():
    mem = InMemoryTemporalCache()
    mem.record('h1', ['a','b'], window_seconds=60)
    assert mem.seen_within('h1','a', 60) is True
    assert mem.host_count() == 1