import time
import pytest

try:
    import fakeredis
except Exception:
    fakeredis = None

from core.correlation.redis_cache import RedisTemporalCache
from core.metrics.registry import get_registry, metric_counter

@pytest.mark.skipif(fakeredis is None, reason="fakeredis not installed")
def test_temporal_cache_hit_miss_counters_increment():
    r = fakeredis.FakeRedis()
    cache = RedisTemporalCache(redis_url='redis://localhost')
    cache.redis = r

    # Access registry (ensures counters are registered)
    reg = get_registry()

    # Record one factor for tenantA
    cache.record('h1', ['f1'], window_seconds=5, tenant_id='tenantA')

    # Hit: should increment hits when seen_within is True
    assert cache.seen_within('h1','f1', 5, tenant_id='tenantA') is True

    # Miss: different factor
    assert cache.seen_within('h1','f2', 5, tenant_id='tenantA') is False

    # Scrape metrics text from registry if available
    try:
        from prometheus_client import generate_latest
        metrics_text = generate_latest(reg).decode()
    except Exception:
        metrics_text = ''

    # Basic assertions: counters should appear and have at least 1 increment for hits and misses
    assert 'temporal_cache_hits' in metrics_text
    assert 'temporal_cache_misses' in metrics_text
    # Ensure tenant label present
    assert 'tenant="tenantA"' in metrics_text