from __future__ import annotations
import time
from src.correlation.dispatcher import correlate
from src.correlation import suppression as _supp

def test_suppression_emits_on_high_fp_ratio(monkeypatch):
    monkeypatch.setenv('SUPPRESSION_ENABLED','1')
    monkeypatch.setenv('SUPPRESS_FP_RATIO','2.0')  # lower threshold
    # Set support higher so emission occurs on final event below
    monkeypatch.setenv('SUPPRESS_MIN_SUPPORT','5')
    monkeypatch.setenv('SUPPRESS_COOLDOWN_SECONDS','10')
    # Reconfigure global correlator (module imported before env vars) and clear state
    sc = _supp.GLOBAL_SUPPRESSION_CORRELATOR
    sc.fp_ratio_threshold = 2.0
    sc.min_support = 5
    sc.cooldown = 10
    sc._stats.clear(); sc._last_emit.clear()
    # Include a secondary stable factor to form pairs consistently
    pair = ['ssl:ja3_rare','net:beacon_periodic','http:user_agent_rare']
    base_ts = time.time()
    # Feed FP contexts to build FP > TP ratio
    for i in range(4):  # build support=4 (<5)
        ev = {'incident_id': f'fx{i}', 'ts': base_ts+i}
        # had_fp=True to increment FP side
        new, d = correlate(ev, pair, had_tp=False, had_fp=True)
    # Fifth event reaches min_support=5 -> emission expected
    ev2 = {'incident_id': 'final_fp', 'ts': base_ts+5}
    new2, d2 = correlate(ev2, pair, had_tp=False, had_fp=True)
    sup = [f for f in new2 if f == 'corr:suppress_low_value']
    assert sup, 'Expected suppression factor emitted'
    assert d2 < 0, 'Suppression delta should be negative'

def test_suppression_requires_support(monkeypatch):
    monkeypatch.setenv('SUPPRESSION_ENABLED','1')
    monkeypatch.setenv('SUPPRESS_FP_RATIO','1.5')
    monkeypatch.setenv('SUPPRESS_MIN_SUPPORT','6')
    sc = _supp.GLOBAL_SUPPRESSION_CORRELATOR
    sc.min_support = 6
    sc.fp_ratio_threshold = 1.5
    sc._stats.clear(); sc._last_emit.clear()
    pair = ['ssl:ja3_rare','net:beacon_periodic','http:user_agent_rare']
    base_ts = time.time()
    # Only 3 FP events => support below threshold
    for i in range(3):
        ev = {'incident_id': f'short{i}', 'ts': base_ts+i}
        correlate(ev, pair, had_tp=False, had_fp=True)
    ev_last = {'incident_id': 'short_last', 'ts': base_ts+4}
    new_last, d_last = correlate(ev_last, pair, had_tp=False, had_fp=True)
    assert 'corr:suppress_low_value' not in new_last