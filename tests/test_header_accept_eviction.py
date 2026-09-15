import os
import pytest

from src.modules.network_hunter import NetworkThreatHunter


def make_accept_freq(total=2005, high_count=600, high_val=3):
    af = {}
    # create some high-frequency entries to be eligible for eviction
    for i in range(high_count):
        af[f'high/{i}'] = high_val
    # remaining entries are low-count (rare)
    for j in range(total - high_count):
        af[f'low/{j}'] = 1
    return af


def test_accept_freq_eviction(monkeypatch):
    # Ensure threshold is defined
    monkeypatch.setenv('ACCEPT_RARE_THRESHOLD', '2')
    nh = NetworkThreatHunter(config=None)
    # Install a large class-level accept frequency map
    NetworkThreatHunter._accept_freq = make_accept_freq(total=2005, high_count=600, high_val=3)
    before = len(NetworkThreatHunter._accept_freq)
    assert before == 2005
    # Trigger header analysis with a new accept value
    headers = {'Accept': 'new/1'}
    nh._analyze_http_headers({'http_headers': headers}, [])
    after = len(NetworkThreatHunter._accept_freq)
    # Eviction should remove high-frequency entries until map size <= 1500
    assert after <= 1500
    # And the map should still contain the newly recorded accept header
    assert 'new/1' in NetworkThreatHunter._accept_freq
