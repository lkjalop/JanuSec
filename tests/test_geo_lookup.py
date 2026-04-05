import os, tempfile, json
from src.enrichment import geoip

def test_cidr_and_range_parsing(tmp_path, monkeypatch):
    p = tmp_path / 'geo.csv'
    p.write_text('# comment\n1.1.1.0/24,AU,AS13335\n2.2.2.0,2.2.2.255,US,AS12345\n')
    monkeypatch.setenv('GEOIP_CSV', str(p))
    # force init
    geoip.initialize_geoip(force_reload=True)
    info = geoip.lookup_ip('1.1.1.1')
    assert info and info.get('country') == 'AU'
    info2 = geoip.lookup_ip('2.2.2.5')
    assert info2 and info2.get('asn') == 'AS12345'
