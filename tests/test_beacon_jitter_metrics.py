import os, time, pytest
from src.modules.network_hunter import NetworkThreatHunter
from src.graph.beacon_synthetic import generate_beacon_series

PROM_AVAILABLE = False
try:  # check if prometheus_client is installed
    import prometheus_client  # type: ignore
    PROM_AVAILABLE = True
except Exception:
    PROM_AVAILABLE = False

@pytest.mark.asyncio
async def test_beacon_high_jitter_no_periodic(fixed_start_ts):
    nh = NetworkThreatHunter(config=None)
    nh.BEACON_MIN_INTERVALS = 3
    nh.BEACON_MIN_DURATION = 1
    events = generate_beacon_series('jit2','10.0.0.88', base_period=1, count=14, jitter=0.8, start_ts=fixed_start_ts)
    last = None
    for ev in events:
        last = await nh.analyze_event(ev)
    assert last is not None
    # With high jitter periodic classification must not occur; beacon_like may or may not fire depending on CV
    assert 'net:beacon_periodic' not in (last['factors'] or [])
    # High jitter should not produce tight periodic explanation if not triggered
    if 'net:beacon_periodic' not in last['factors']:
        assert 'beacon_explain' not in last, 'Should not attach explain when beacon not classified'

@pytest.mark.asyncio
async def test_beacon_metrics_increment(fixed_start_ts, monkeypatch):
    if not PROM_AVAILABLE:
        pytest.skip('prometheus_client not installed')
    nh = NetworkThreatHunter(config=None)
    nh.BEACON_MIN_INTERVALS = 3
    nh.BEACON_MIN_DURATION = 1
    # Ensure counters exist
    assert hasattr(nh.__class__, 'factor_counter')
    before_like = nh.__class__.factor_counter.labels(factor='net:beacon_periodic')._value.get() if hasattr(nh.__class__.factor_counter.labels(factor='net:beacon_periodic'), '_value') else 0  # type: ignore
    events = generate_beacon_series('metricsHost','10.0.0.60', base_period=1, count=12, jitter=0.0, start_ts=fixed_start_ts)
    for ev in events:
        await nh.analyze_event(ev)
    after_like = nh.__class__.factor_counter.labels(factor='net:beacon_periodic')._value.get() if hasattr(nh.__class__.factor_counter.labels(factor='net:beacon_periodic'), '_value') else before_like  # type: ignore
    assert after_like >= before_like + 1, 'Beacon like counter did not increment as expected'
