import time
from src.core.analysis.beacon_detector import periodicity_from_timestamps


def test_beacon_detector_periodicity():
    # simulate periodic timestamps every 60s for 10 samples
    start = time.time()
    ts = [start + (i * 60.0) for i in range(10)]
    score, details = periodicity_from_timestamps(ts)
    assert score >= 0.5
    assert details.get('sample_count') == 10
