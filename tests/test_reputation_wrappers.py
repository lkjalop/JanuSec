from src.core.reputation import wrappers, cache


def test_mx_is_free_provider_monkeypatch(monkeypatch):
    # monkeypatch the internal mx lookup to return a known provider
    def fake_mx(domain):
        return ['aspmx.l.google.com']
    monkeypatch.setattr(wrappers, '_perform_mx_lookup', fake_mx)
    cache.clear()
    assert wrappers.mx_is_free_provider('example.com') is True


def test_whois_age_monkeypatch(monkeypatch):
    # return a fake whois creation date
    class FakeWhois:
        creation_date = '2000-01-01T00:00:00'

    def fake_whois(domain):
        return {'creation_date': '2000-01-01T00:00:00'}

    monkeypatch.setattr(wrappers, '_perform_whois', fake_whois)
    cache.clear()
    days = wrappers.whois_domain_age_days('example.com')
    assert days is not None and days > 5000


def test_geoip_lookup_cache(monkeypatch):
    called = {'count': 0}

    def fake_geo(ip):
        called['count'] += 1
        return {'country': 'US'}

    monkeypatch.setattr(wrappers, '_perform_geoip', fake_geo)
    cache.clear()
    res1 = wrappers.geoip_lookup('8.8.8.8')
    res2 = wrappers.geoip_lookup('8.8.8.8')
    assert res1 == res2
    assert called['count'] == 1


def test_whois_circuit_breaker(monkeypatch):
    # Simulate whois failing to trigger circuit breaker
    failures = {'count':0}

    def fake_whois(domain):
        failures['count'] += 1
        raise RuntimeError('whois failure')

    monkeypatch.setattr('src.core.reputation.wrappers._perform_whois', fake_whois)
    # clear cache and cb state
    cache.clear()
    # make several calls to exceed threshold
    ok = False
    for i in range(5):
        try:
            _ = wrappers.whois_domain_age_days('bad.example')
        except Exception:
            ok = True
    # The internal failure count should have incremented
    assert failures['count'] >= 1
