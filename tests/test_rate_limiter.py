from src.core.rate_limiter import RateLimiter


def test_local_rate_limiter_counts():
    r1 = RateLimiter(per_min=3)
    actor = 'user-x'
    assert r1.allow(actor) is True
    assert r1.allow(actor) is True
    assert r1.allow(actor) is True
    assert r1.allow(actor) is False
