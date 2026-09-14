from __future__ import annotations
import textwrap, sys

def test_geoip_lookup_and_enrich(tmp_path, monkeypatch):
    data = textwrap.dedent("""
    # start_ip,end_ip,country,asn
    1.1.1.0,1.1.1.255,AU,AS13335
    8.8.8.0,8.8.8.255,US,AS15169
    """).strip()
    csv_path = tmp_path / 'geoip_demo.csv'
    csv_path.write_text(data, encoding='utf-8')
    monkeypatch.setenv('GEOIP_CSV', str(csv_path))
    # reload module to force reading custom csv
    sys.modules.pop('src.enrichment.geoip', None)
    from src.enrichment.geoip import lookup_ip, enrich_event
    info = lookup_ip('8.8.8.8')
    assert info and info['country'] == 'US'
    event = {'dst_ip':'1.1.1.1'}
    enrich_event(event)
    assert 'geo' in event and 'dst_ip' in event['geo']
    assert event['geo']['dst_ip']['country'] == 'AU'
