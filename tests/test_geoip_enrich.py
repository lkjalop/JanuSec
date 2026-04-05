import os
from src.core.enrichment.geoip_enrich import enrich_event_with_geoip
from src.core.detectors.geo_rules import detect_geo_risks


def test_enrich_localhost():
    e = {'src_ip': '127.0.0.1'}
    out = enrich_event_with_geoip(e)
    assert 'enrichment' in out


def test_geo_rules_bad_asn(tmp_path, monkeypatch):
    # create a sample bad ASN file
    bad = tmp_path / 'bad_asns.txt'
    bad.write_text('AS12345\n67890\n')
    monkeypatch.setenv('BAD_ASN_LIST_PATH', str(bad))
    enrichment = {'geo': {'ip': '1.2.3.4', 'country': 'US'}, 'asn': {'asn': 'AS12345', 'provider': 'BadNet'}}
    res = detect_geo_risks(enrichment)
    assert any(r.get('factor') == 'geo:known_bad_asn' for r in res)
