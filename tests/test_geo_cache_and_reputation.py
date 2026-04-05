import json
import types
import tempfile
import os

from src.enrichment.geo_integration import enrich_event_with_geo


def test_cache_and_reputation(monkeypatch, tmp_path):
    # prepare a fake enricher that returns ASN 65000
    info = {
        'country': 'CacheLand',
        'country_code': 'CL',
        'city': 'CacheCity',
        'latitude': 0.1,
        'longitude': 0.2,
        'asn': 65000,
        'asn_org': 'CacheOrg',
        'asn_cidr': '198.51.100.0/24',
    }

    app = types.SimpleNamespace()
    state = types.SimpleNamespace()
    call_count = {'n': 0}
    def enricher(ip):
        call_count['n'] += 1
        return dict(info)
    state.geo_asn_enricher = enricher
    app.state = state

    # create a temporary ASN reputation file
    rep = {"65000": {"score": 0.9, "note": "suspicious"}}
    p = tmp_path / 'asn_rep.json'
    p.write_text(json.dumps(rep))

    # load reputation into module
    from src.core.enrichment import asn_reputation
    asn_reputation.load_reputation(str(p))

    # ensure cache is fresh (use get_global_cache to get in-memory)
    from src.core.enrichment.geo_cache import get_global_cache
    cache = get_global_cache()
    # clear any existing
    cache._mem.store.clear()

    from src.api.metrics_init import COUNTERS
    COUNTERS['geo_enrichment_calls'] = COUNTERS.get('geo_enrichment_calls')

    ev = {'src_ip': '9.9.9.9'}
    enrich_event_with_geo(app, ev)
    # first call should attach asn and reputation
    assert 'asn' in ev and ev['asn']['asn'] == 65000
    assert 'reputation' in ev['asn'] and ev['asn']['reputation']['score'] == 0.9

    # now simulate second call to hit cache
    ev2 = {'src_ip': '9.9.9.9'}
    enrich_event_with_geo(app, ev2)
    # enricher should have been called only once (second call served from cache)
    assert call_count['n'] == 1
