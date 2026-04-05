from __future__ import annotations
import time
from src.correlation.dispatcher import correlate
import importlib
from src.correlation import campaigns as _campaigns


def test_campaign_emission_threshold(monkeypatch):
    monkeypatch.setenv('CAMPAIGNS_ENABLED','1')
    monkeypatch.setenv('CAMPAIGN_MIN_INCIDENTS','3')
    monkeypatch.setenv('CAMPAIGN_WINDOW_SECONDS','3600')
    # Use small cooldown so test can check later non-emission
    monkeypatch.setenv('CAMPAIGN_COOLDOWN_SECONDS','300')
    pivot_factor = 'net:beacon_periodic'
    base_ts = time.time()
    # First two incidents: should not yet emit
    for iid in ('inc1','inc2'):
        ev = {'incident_id': iid, 'ts': base_ts}
        new, d = correlate(ev, [pivot_factor])
        assert all(not f.startswith('campaign:') for f in new)
    # Third distinct incident crosses threshold
    ev3 = {'incident_id': 'inc3', 'ts': base_ts+5}
    new3, d3 = correlate(ev3, [pivot_factor])
    camp = [f for f in new3 if f.startswith('campaign:')]
    assert camp, 'Expected campaign factor after threshold'
    assert d3 > 0
    # Immediate fourth incident should NOT emit again due to cooldown
    ev4 = {'incident_id': 'inc4', 'ts': base_ts+10}
    new4, d4 = correlate(ev4, [pivot_factor])
    assert all(not f.startswith('campaign:') for f in new4)


def test_campaign_cooldown_allows_after_time(monkeypatch):
    monkeypatch.setenv('CAMPAIGNS_ENABLED','1')
    monkeypatch.setenv('CAMPAIGN_MIN_INCIDENTS','2')
    monkeypatch.setenv('CAMPAIGN_COOLDOWN_SECONDS','1')
    # Reconfigure existing global correlator (module already imported before env set)
    _campaigns.GLOBAL_CAMPAIGN_CORRELATOR.min_incidents = 2
    _campaigns.GLOBAL_CAMPAIGN_CORRELATOR.cooldown = 1
    pivot_factor = 'net:asn_high_risk'
    t0 = time.time()
    ev1 = {'incident_id': 'ia', 'ts': t0}
    # First incident alone insufficient
    correlate(ev1, [pivot_factor])
    time.sleep(0.05)
    # Second incident hits threshold (min_incidents=2)
    ev2 = {'incident_id': 'ib', 'ts': t0+0.05}
    new2, _ = correlate(ev2, [pivot_factor])
    first = [f for f in new2 if f.startswith('campaign:')]
    assert first, 'Expected campaign factor on second incident'
    # Within cooldown — should not emit
    ev3 = {'incident_id': 'ic', 'ts': t0+0.1}
    new3,_ = correlate(ev3, [pivot_factor])
    assert all(not f.startswith('campaign:') for f in new3)
    # After cooldown; manipulate time by sleeping slightly over 1s total
    time.sleep(1.05)
    ev4 = {'incident_id': 'id', 'ts': time.time()}
    new4,_ = correlate(ev4, [pivot_factor])
    again = [f for f in new4 if f.startswith('campaign:')]
    assert again