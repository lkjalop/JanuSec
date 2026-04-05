import pytest, time
from src.modules.network_hunter import NetworkThreatHunter
from src.graph.beacon_synthetic import generate_beacon_series

@pytest.mark.asyncio
async def test_lomb_scargle_error_path(monkeypatch):
    nh = NetworkThreatHunter(config=None)
    nh.BEACON_MIN_INTERVALS = 3
    nh.BEACON_MIN_DURATION = 1
    # Force flags so code enters lombscargle block
    import src.modules.network_hunter as nh_mod
    monkeypatch.setattr(nh_mod, '_HAVE_LOMB', True, raising=False)
    # Create a fake lombscargle that raises
    def boom(ts, y, freqs):
        raise RuntimeError('synthetic failure')
    monkeypatch.setattr(nh_mod, 'lombscargle', boom, raising=False)
    events = generate_beacon_series('lerr','10.0.0.99', base_period=1, count=10, jitter=0.0, start_ts=time.time())
    last = None
    for ev in events:
        last = await nh.analyze_event(ev)
    assert last is not None
    # Should still have at least beacon_like (periodic may or may not appear depending on CV)
    assert 'net:beacon_periodic' in last['factors']
