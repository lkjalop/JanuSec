import os, sys, pathlib

root = pathlib.Path(__file__).resolve().parents[1]
src = root / 'src'
if str(src) not in sys.path:
    sys.path.insert(0, str(src))

from core.time_of_day import TOD


def test_time_of_day_basic():
    key = 'host1'
    # clear any existing profile
    try:
        TOD._profiles.pop(key, None)
    except Exception:
        pass
    # Update specific hours
    for _ in range(10):
        TOD.update(key, hour=3, value=1.0)
    for _ in range(2):
        TOD.update(key, hour=15, value=1.0)
    prof = TOD.get_profile(key)
    assert prof is not None
    z3 = prof.z_for_hour(3)
    z15 = prof.z_for_hour(15)
    # hour 3 should be above mean, hour 15 below the mean
    assert z3 > z15
    div = TOD.divergence(key, 3)
    assert 'z' in div and 'mean' in div and 'stddev' in div
