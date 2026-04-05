import pytest, time
from src.modules.network_hunter import NetworkThreatHunter
from src.graph.beacon_synthetic import generate_beacon_series

@pytest.mark.asyncio
async def test_beacon_periodic_factor(fixed_start_ts, monkeypatch):
    nh = NetworkThreatHunter(config=None)
    # Speed up detection: lower required intervals and threshold for test
    nh.BEACON_MIN_INTERVALS = 3  # need at least 4 timestamps
    nh.BEACON_MIN_DURATION = 1
    # Make detection more sensitive for deterministic test (tighter CV threshold)
    nh.BEACON_CV_THRESHOLD = 0.5  # ensure periodic_gate triggers on low jitter sequence
    events = generate_beacon_series('hostA','10.0.0.5', base_period=1, count=12, jitter=0.0, start_ts=fixed_start_ts)
    last_factors = []
    last_res = None
    for ev in events:
        last_res = await nh.analyze_event(ev)
        last_factors = last_res['factors']
    assert any(f.startswith('net:beacon_') for f in last_factors), f"Beacon factors missing: {last_factors}"
    assert last_res is not None and 'beacon_explain' in last_res, 'Missing beacon_explain metadata on detection'
