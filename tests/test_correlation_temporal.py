import time
from src.correlation.temporal import GLOBAL_TEMPORAL_CORRELATOR


def _mk_event(host: str, ts: float):
    return {'event_id': f'e-{host}-{ts}', 'host': host, 'ts': ts}


def test_temporal_correlation_positive_sequence():
    c = GLOBAL_TEMPORAL_CORRELATOR
    # Reset internal state for test isolation
    c.events.clear(); c.last_emit.clear()
    base = time.time()
    # Step 1 rare_lineage
    e1 = _mk_event('h1', base)
    nf, d = c.ingest(e1, ['endpoint:rare_lineage'])
    assert not nf
    # Step 2 lsass_access
    e2 = _mk_event('h1', base+10)
    nf, d = c.ingest(e2, ['endpoint:lsass_access'])
    assert not nf
    # Step 3 beacon_periodic triggers correlation
    e3 = _mk_event('h1', base+20)
    nf, d = c.ingest(e3, ['net:beacon_periodic'])
    assert 'corr:multi_stage_lateral_beacon' in nf
    assert d > 0
    # Cooldown: immediate repeat should not emit
    e4 = _mk_event('h1', base+25)
    nf2, d2 = c.ingest(e4, ['net:beacon_periodic'])
    assert not nf2 and d2 == 0


def test_temporal_correlation_negative_out_of_order():
    c = GLOBAL_TEMPORAL_CORRELATOR
    c.events.clear(); c.last_emit.clear()
    base = time.time()
    # Start with lsass_access (missing initial rare_lineage)
    e1 = _mk_event('h2', base)
    c.ingest(e1, ['endpoint:lsass_access'])
    # Then beacon
    e2 = _mk_event('h2', base+5)
    nf, d = c.ingest(e2, ['net:beacon_periodic'])
    assert not nf and d == 0
    # Add rare_lineage late (should not retroactively match previous events order)
    e3 = _mk_event('h2', base+10)
    nf2, d2 = c.ingest(e3, ['endpoint:rare_lineage'])
    assert not nf2 and d2 == 0


def test_temporal_window_and_cooldown(monkeypatch):
    # Use a fresh correlator instance to avoid cross-test state
    from src.correlation.temporal import TemporalCorrelator
    c = TemporalCorrelator()
    now = 1000000.0
    # configure window small for test
    monkeypatch.setenv('CORR_TEMPORAL_WINDOW_SEC','10')
    monkeypatch.setenv('CORR_TEMPORAL_COOLDOWN_SEC','30')
    c.window_seconds = 10
    c.cooldown_seconds = 30
    # Event 1: step 1 at t=now-20 (outside window)
    e1 = {'host_id': 'host-x', 'ts': now - 20}
    f1 = ['endpoint:rare_lineage']
    nf, d = c.ingest(e1, f1)
    assert nf == []
    # Event 2: step 2 at t=now-5 (inside window)
    e2 = {'host_id': 'host-x', 'ts': now - 5}
    f2 = ['endpoint:lsass_access']
    nf, d = c.ingest(e2, f2)
    assert nf == []
    # Event 3: step 3 at t=now (inside window) -> should NOT match because step1 aged out
    e3 = {'host_id': 'host-x', 'ts': now}
    f3 = ['net:beacon_periodic']
    nf, d = c.ingest(e3, f3)
    assert nf == []
    # Now provide a fresh sequence inside window
    e1b = {'host_id': 'host-x', 'ts': now}
    f1b = ['endpoint:rare_lineage']
    nf, d = c.ingest(e1b, f1b)
    assert nf == []
    e2b = {'host_id': 'host-x', 'ts': now + 1}
    f2b = ['endpoint:lsass_access']
    nf, d = c.ingest(e2b, f2b)
    assert nf == []
    e3b = {'host_id': 'host-x', 'ts': now + 2}
    f3b = ['net:beacon_periodic']
    nf, d = c.ingest(e3b, f3b)
    assert nf == ['corr:multi_stage_lateral_beacon']
    # Attempt immediate re-sequence within cooldown -> should not emit again
    e1c = {'host_id': 'host-x', 'ts': now + 3}
    f1c = ['endpoint:rare_lineage']
    c.ingest(e1c, f1c)
    e2c = {'host_id': 'host-x', 'ts': now + 4}
    f2c = ['endpoint:lsass_access']
    c.ingest(e2c, f2c)
    e3c = {'host_id': 'host-x', 'ts': now + 5}
    f3c = ['net:beacon_periodic']
    nf, d = c.ingest(e3c, f3c)
    assert nf == []
