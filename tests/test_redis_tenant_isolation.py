import pytest

try:
    import fakeredis
except Exception:
    fakeredis = None

from core.correlation.redis_cache import RedisTemporalCache


@pytest.mark.skipif(fakeredis is None, reason="fakeredis not installed")
def test_tenant_isolation_between_two_tenants():
    r = fakeredis.FakeRedis()
    cache = RedisTemporalCache(redis_url='redis://localhost')
    cache.redis = r

    # Record same host name under tenant A and tenant B with different factors
    cache.record('shared-host', ['fA'], window_seconds=60, tenant_id='tenantA')
    cache.record('shared-host', ['fB'], window_seconds=60, tenant_id='tenantB')

    # Each tenant should only see their own factor
    assert cache.seen_within('shared-host', 'fA', 10, tenant_id='tenantA') is True
    assert cache.seen_within('shared-host', 'fB', 10, tenant_id='tenantB') is True

    # Cross-tenant checks must be False
    assert cache.seen_within('shared-host', 'fB', 10, tenant_id='tenantA') is False
    assert cache.seen_within('shared-host', 'fA', 10, tenant_id='tenantB') is False

    # Host sets should be per-tenant
    assert cache.host_count_for_tenant('tenantA') >= 1
    assert cache.host_count_for_tenant('tenantB') >= 1