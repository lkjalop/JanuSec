import pytest
from src.modules.network_hunter import NetworkThreatHunter
from src.graph.beacon_synthetic import generate_beacon_series

@pytest.mark.asyncio
async def test_beacon_multiscale_explanation(fixed_start_ts):
    nh = NetworkThreatHunter(config=None)
    nh.BEACON_MIN_INTERVALS = 3
    nh.BEACON_MIN_DURATION = 1
    nh.BEACON_CV_THRESHOLD = 0.5
    events = generate_beacon_series('mscale','10.0.0.9', base_period=2, count=16, jitter=0.0, start_ts=fixed_start_ts)
    last = None
    for ev in events:
        last = await nh.analyze_event(ev)
    assert last is not None
    assert 'beacon_explain' in last, 'Expected beacon_explain for multi-scale detection'
    explain = last['beacon_explain']
    for key in ('best_scale','cv','periodic_strength','mean_interval','interval_count','duration'):
        assert key in explain, f"Missing {key} in explanation"
    # With zero jitter the raw scale should often be best (scale 1)
    assert explain['best_scale'] in (1,2,4)
    assert explain['cv'] <= 0.01, f"Unexpected CV for zero jitter series: {explain['cv']}"
    # Mean interval should reflect chosen scale: raw scale 1 => ~2, scale 2 => ~4, scale 4 => ~8
    expected = 2 * explain['best_scale']
    assert abs(explain['mean_interval'] - expected) < 0.01, f"Mean interval off: got {explain['mean_interval']} expected {expected} (scale {explain['best_scale']})"