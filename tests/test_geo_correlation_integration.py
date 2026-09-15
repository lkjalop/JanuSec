from __future__ import annotations
import time, sys

from src.correlation.dispatcher import correlate
from src.modules.network_hunter import NetworkThreatHunter

class DummyConfig(dict):
    pass

def test_geo_and_correlation_confidence_cap(monkeypatch, tmp_path):
    # Provide small geo CSV
    csv_data = """# start_ip,end_ip,country,asn
1.1.1.0,1.1.1.255,AU,AS13335
8.8.8.0,8.8.8.255,US,AS15169
""".strip()
    geo_path = tmp_path / 'geoip_demo.csv'
    geo_path.write_text(csv_data, encoding='utf-8')
    monkeypatch.setenv('GEOIP_CSV', str(geo_path))
    # Reset geo module to reload
    sys.modules.pop('src.enrichment.geoip', None)
    from src.enrichment.geoip import enrich_event  # noqa: F401
    # Ensure network_hunter picks up the reloaded geoip binding
    import importlib
    import src.modules.network_hunter as _nh
    importlib.reload(_nh)
    from src.modules.network_hunter import NetworkThreatHunter
    hunter = NetworkThreatHunter(DummyConfig())
    # Craft event with geo fields and factors leading to correlation temporal pattern
    base = time.time()
    host = 'geoHost'
    # Simulate sequence for temporal correlation on same host
    correlate({'host':host,'ts':base}, ['endpoint:rare_lineage'])
    correlate({'host':host,'ts':base+1}, ['endpoint:lsass_access'])
    # Network event producing beacon + geo factors
    event = {'host':host, 'ts':base+2, 'dst_ip':'1.1.1.1'}
    # analyze_event is async
    import asyncio
    res = asyncio.get_event_loop().run_until_complete(hunter.analyze_event(event))
    # Add final correlation hop
    new_corr, d = correlate({'host':host,'ts':base+2.5}, ['net:beacon_periodic'], had_tp=True, had_fp=False)
    # Ensure confidence cap maintained
    assert res['confidence_delta'] <= hunter.MAX_CONFIDENCE
    # Result should include geo heuristic factors if enrichment succeeded (best-effort)
    # Either net:country_rare or net:asn_high_risk may appear depending on order
    assert any(f.startswith('net:country_') or f.startswith('net:asn_') for f in res['factors'])