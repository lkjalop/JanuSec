import pytest, time, types
from src.modules.network_hunter import NetworkThreatHunter
from src.graph.beacon_synthetic import generate_beacon_series

@pytest.mark.asyncio
async def test_beacon_lomb_scargle_path_skipped_when_absent(monkeypatch):
    # Simulate SciPy absence regardless of environment
    nh = NetworkThreatHunter(config=None)
    nh.BEACON_MIN_INTERVALS = 3
    nh.BEACON_MIN_DURATION = 1
    # Force internal flags to simulate no lombscargle available
    monkeypatch.setattr('src.modules.network_hunter._HAVE_LOMB', False, raising=False)
    monkeypatch.setattr('src.modules.network_hunter.lombscargle', None, raising=False)
    events = generate_beacon_series('h1','10.0.0.9', base_period=1, count=10, jitter=0.0, start_ts=time.time())
    last = None
    for ev in events:
        last = await nh.analyze_event(ev)
    assert last is not None
    # Should still detect via cv/autocorr (factor present)
    assert 'net:beacon_periodic' in last['factors']

@pytest.mark.asyncio
async def test_beacon_lomb_scargle_path_when_present(monkeypatch):
    # If SciPy is installed this exercises real call; otherwise we inject a fake lombscargle
    nh = NetworkThreatHunter(config=None)
    nh.BEACON_MIN_INTERVALS = 3
    nh.BEACON_MIN_DURATION = 1

    # If the real lombscargle isn't there, stub it with deterministic power output
    import src.modules.network_hunter as nh_mod
    if not getattr(nh_mod, '_HAVE_LOMB', False) or nh_mod.lombscargle is None:
        def fake_lomb(ts, y, freqs):
            import numpy as np  # type: ignore
            # Return an array with a clear peak to simulate periodic signal detection
            return np.linspace(0.0, 1.0, len(freqs))
        monkeypatch.setattr(nh_mod, '_HAVE_LOMB', True, raising=False)
        monkeypatch.setattr(nh_mod, 'lombscargle', fake_lomb, raising=False)

    events = generate_beacon_series('h2','10.0.0.10', base_period=1, count=14, jitter=0.0, start_ts=time.time())
    last = None
    for ev in events:
        last = await nh.analyze_event(ev)
    assert last is not None
    # Expect stronger periodic classification due to lomb power path (net:beacon_periodic)
    assert 'net:beacon_periodic' in last['factors']
    assert 'net:beacon_periodic' in last['factors'], f"Expected periodic factor, got {last['factors']}"
