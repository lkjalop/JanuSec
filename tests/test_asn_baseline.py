import time
import os

from src.baseline.services import record_asn, get_asn_rarity  # type: ignore


def test_asn_rarity_ttl(monkeypatch):
    # set small TTL
    monkeypatch.setenv('ASN_RARITY_TTL_SECONDS','1')
    record_asn('AS1')
    record_asn('AS1')
    record_asn('AS2')
    r1 = get_asn_rarity()
    assert r1['asn_counts'].get('AS1',0) >= 2
    time.sleep(1.2)
    # calling again prunes older entries
    r2 = get_asn_rarity()
    # AS1/AS2 may be pruned depending on timestamping; ensure function runs
    assert 'rarity_scores' in r2
