import time

try:
    from baseline.services import record_dns_event, record_asn, get_nxdomain_baseline, get_asn_rarity  # type: ignore
except Exception:
    from src.baseline.services import record_dns_event, record_asn, get_nxdomain_baseline, get_asn_rarity  # type: ignore

from src.graph.reconstruction import path_factors, score_path  # type: ignore


def _drain_baselines():
    # crude reset by recording successes to dilute prior state
    for _ in range(5):
        record_dns_event(True)


def test_nxdomain_spike_factor():
    _drain_baselines()
    # produce failures to elevate rate beyond threshold heuristic
    for _ in range(20):
        record_dns_event(False)
    # few successes
    for _ in range(5):
        record_dns_event(True)
    nx = get_nxdomain_baseline()
    # ensure rate surpasses dynamic threshold (may be threshold=rate+0.15 so not > threshold yet) -> assert mechanism sets threshold >=0.35 then generate more failures
    if nx['rate'] < nx['threshold']:
        for _ in range(15):
            record_dns_event(False)
    factors = path_factors([{'domain': 'example.com'}])
    assert 'nxdomain_spike' in factors, f"Expected nxdomain_spike in factors; baseline={nx} got={factors}"
    contrib, msg = factors['nxdomain_spike']
    assert contrib > 0
    assert 'nxdomain rate' in msg or 'nxdomain rate' in msg.lower()


def test_asn_rarity_factor():
    # record multiple ASN events; one rare, one common
    common_asn = 'AS12345'
    rare_asn = 'AS54321'
    for _ in range(50):
        record_asn(common_asn)
    for _ in range(1):
        record_asn(rare_asn)
    rarity = get_asn_rarity()
    assert rarity['rarity_scores'][rare_asn] > rarity['rarity_scores'][common_asn]
    path = [{'asn': rare_asn, 'domain': 'rare.example'}]
    factors = path_factors(path)
    assert 'asn_rarity' in factors, f"asn_rarity missing; rarity={rarity} factors={factors}"
    score = score_path(path)
    assert score['contributions']['asn_rarity']['contribution'] > 0
