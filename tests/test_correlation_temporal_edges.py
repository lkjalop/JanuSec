from __future__ import annotations
import time
from src.correlation.temporal import TemporalCorrelator


def make_event(host: str, ts: float):
    return {'host': host, 'ts': ts}


def test_temporal_expiry_window():
    c = TemporalCorrelator()
    # Shrink window for test
    c.window_seconds = 10
    base = time.time()
    # First two steps occur, then we advance beyond window before third
    c.ingest(make_event('h1', base), ['endpoint:rare_lineage'])
    c.ingest(make_event('h1', base + 2), ['endpoint:lsass_access'])
    # Advance beyond window -> purge earlier
    nf, d = c.ingest(make_event('h1', base + 25), ['net:beacon_periodic'])
    assert not nf and d == 0.0, 'Should not match due to expiry of earlier steps'


def test_temporal_cooldown():
    c = TemporalCorrelator()
    c.cooldown_seconds = 30
    base = time.time()
    # Complete sequence
    nf1, d1 = c.ingest(make_event('h2', base), ['endpoint:rare_lineage'])
    nf2, d2 = c.ingest(make_event('h2', base + 1), ['endpoint:lsass_access'])
    nf3, d3 = c.ingest(make_event('h2', base + 2), ['net:beacon_periodic'])
    assert (nf1 == []) and (nf2 == [])
    assert 'corr:multi_stage_lateral_beacon' in nf3
    # Repeat sequence within cooldown
    c.ingest(make_event('h2', base + 3), ['endpoint:rare_lineage'])
    c.ingest(make_event('h2', base + 4), ['endpoint:lsass_access'])
    nf4, d4 = c.ingest(make_event('h2', base + 5), ['net:beacon_periodic'])
    assert nf4 == [] and d4 == 0.0, 'Cooldown should suppress second emission'
    # After cooldown
    c.ingest(make_event('h2', base + 40), ['endpoint:rare_lineage'])
    c.ingest(make_event('h2', base + 41), ['endpoint:lsass_access'])
    nf5, d5 = c.ingest(make_event('h2', base + 42), ['net:beacon_periodic'])
    assert 'corr:multi_stage_lateral_beacon' in nf5 and d5 > 0.0, 'Emission should occur post cooldown'
