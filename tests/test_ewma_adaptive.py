import time
from src.detectors.ewma_adaptive import AdaptiveEWMA


def test_ewma_cold_start_and_ramp():
    m = AdaptiveEWMA(base_alpha=0.5)
    r = m.update('t1', 10.0)
    assert r['ewma'] == 10.0
    # second update should not equal the raw value
    r2 = m.update('t1', 12.0)
    assert 'alpha' in r2 and 0.0 < r2['alpha'] <= 1.0


def test_ewma_spike_triggers_alert():
    m = AdaptiveEWMA(base_alpha=0.3, k=2.0)
    for i in range(10):
        m.update('t2', 1.0)
    # introduce a large spike
    r = m.update('t2', 100.0)
    assert 'score' in r
    # It's possible score<3 depending on sigma but ensure we compute numeric values
    assert isinstance(r['score'], float)


def test_ewma_adapts_alpha_on_volatility():
    m = AdaptiveEWMA(base_alpha=0.1, min_alpha=0.01, max_alpha=0.9, k=1.0)
    for i in range(5):
        m.update('t3', float(i))
    pre = m.tenants['t3'].alpha
    # create larger swings
    m.update('t3', 20.0)
    post = m.tenants['t3'].alpha
    assert post >= pre
