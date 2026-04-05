from src.core.enrichment.geo_asn_enricher import enrich_ip


def test_enrich_invalid_ip():
    res = enrich_ip('not-an-ip')
    assert res['ip'] == 'not-an-ip'
    assert res['country'] is None


def test_enrich_local_ip():
    # 127.0.0.1 is valid but likely not in GeoIP DB; ensure no crash
    res = enrich_ip('127.0.0.1')
    assert res['ip'] == '127.0.0.1'
    assert 'country' in res
