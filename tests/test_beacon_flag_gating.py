import os, pytest
from src.modules.network_hunter import NetworkThreatHunter
from src.graph.beacon_synthetic import generate_beacon_series

@pytest.mark.asyncio
async def test_beacon_multiscale_flag_gating(monkeypatch, fixed_start_ts):
    # Disable multiscale via env var and ensure best_scale stays 1
    monkeypatch.setenv('MULTISCALE_BEACON_ENABLED','0')
    nh = NetworkThreatHunter(config=None)
    nh.BEACON_MIN_INTERVALS = 3
    nh.BEACON_MIN_DURATION = 1
    events = generate_beacon_series('flagA','10.10.10.10', base_period=1, count=12, jitter=0.0, start_ts=fixed_start_ts)
    last = None
    for ev in events:
        last = await nh.analyze_event(ev)
    assert last and 'beacon_explain' in last, 'Expected beacon explanation when factor triggers'
    assert last['beacon_explain']['best_scale'] == 1, f"Multiscale disabled but best_scale != 1: {last['beacon_explain']}"
