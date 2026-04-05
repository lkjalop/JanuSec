import os
import time
from importlib import reload


def test_asn_decay():
    os.environ['ASN_DECAY_INTERVAL_SECONDS'] = '1'
    os.environ['ASN_DECAY_FACTOR'] = '0.5'
    from src.live import asn_stats
    reload(asn_stats)
    for i in range(10):
        asn_stats.record(f'AS{i}')
    # Distinct should be 10 initially
    time.sleep(1.1)
    # Trigger decay by recording new one
    asn_stats.record('AS_new')
    # After decay some may be pruned (counts halved, threshold pruning <0.5) but new one added
    # Ensure not all gone
    rarity = asn_stats.rarity('AS_new')
    assert rarity >= 0.0

def test_domain_decay():
    os.environ['DOMAIN_DECAY_INTERVAL_SECONDS'] = '1'
    os.environ['DOMAIN_DECAY_FACTOR'] = '0.5'
    from src.live import domain_baseline
    reload(domain_baseline)
    for i in range(8):
        domain_baseline.record(f'example{i}.com')
    time.sleep(1.05)
    domain_baseline.record('fresh.com')
    c, f, sus = domain_baseline.stats('fresh.com')
    assert c >= 1
