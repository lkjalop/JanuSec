import time
from src.core.detectors.beaconing import detect_beaconing
from src.core.detectors.nxdomain_spike import detect_nxdomain_spike

class DummyRuntime:
    def __init__(self):
        self.beacon_trackers = {}
        self.nx_rate_tracker = {}


def test_beaconing_detector_detects_periodic_sequence():
    rt = DummyRuntime()
    now = time.time()
    # create periodic timestamps every 60s for 8 samples
    rt.beacon_trackers['hostA'] = [now + i*60 for i in range(8)]
    res = detect_beaconing(rt)
    assert isinstance(res, list)
    assert any(r.get('factor') == 'net_beaconing_periodic' for r in res)


def test_nxdomain_spike_detector_detects_high_rate():
    rt = DummyRuntime()
    # producer with 10 samples, 7 true entries -> rate 0.7
    rt.nx_rate_tracker['zeek:1'] = [1,1,1,1,1,1,1,0,0,0]
    res = detect_nxdomain_spike(rt, threshold=0.5, min_samples=5)
    assert isinstance(res, list)
    assert any(r.get('factor') == 'nxdomain_rate_high' for r in res)


def test_asn_rarity_detector_with_injected_ips():
    rt = DummyRuntime()
    # inject a fake ip list into runtime.test_ips and provide a minimal asn_stats via monkeypatching
    rt.test_ips = ['8.8.8.8']
    # create a shim runtime attribute to allow import path to work during test
    old_mod = None
    try:
        import sys
        import types
        old_mod = sys.modules.get('src.live')
        mod = types.SimpleNamespace()
        def lookup_asn(ip):
            return 'AS15169' if ip == '8.8.8.8' else None
        class ASStats:
            def rarity(self, asn):
                return 0.95 if asn=='AS15169' else 0.1
            def percentile(self, asn):
                return 0.99 if asn=='AS15169' else 0.01
        setattr(mod, 'lookup_asn', lookup_asn)
        setattr(mod, 'asn_stats', ASStats())
        sys.modules['src.live'] = mod
    except Exception:
        pass
    from src.core.detectors.asn_rarity import detect_asn_rarity
    res = detect_asn_rarity(rt, threshold=0.9)
    assert isinstance(res, list)
    assert any(r.get('factor') == 'asn_rare' for r in res)
    try:
        import sys
        if old_mod is None:
            sys.modules.pop('src.live', None)
        else:
            sys.modules['src.live'] = old_mod
    except Exception:
        pass


def test_file_signature_mismatch_detector():
    rt = DummyRuntime()
    # Create a synthetic file entry with reported_name .exe but no pe_info.is_pe
    files = [{'sha256':'deadbeef','reported_name':'suspicious.exe','pe_info':{'is_pe':False}}]
    from src.core.detectors.file_signature_mismatch import detect_file_signature_mismatch
    res = detect_file_signature_mismatch(rt, files)
    assert isinstance(res, list)
    assert any(r.get('factor') == 'file_signature_mismatch' for r in res)
