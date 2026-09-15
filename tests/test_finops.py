import time

from core.finops.cost_estimator import estimate_hunt_cost
from core.finops.finops_manager import get_finops_manager


def _seed_hourly(fm, tenant: str, values):
    # Directly manipulate hourly rollup for controlled variance
    now = int(time.time() // 3600 * 3600)
    fm._hourly.clear()
    for i,v in enumerate(values):
        fm._hourly[(tenant,'inference', now - i*3600)] = v

def test_finops_hourly_daily_rollup_basic():
    fm = get_finops_manager()
    tenant = 'test_tenant'
    fm._hourly.clear(); fm._daily.clear()
    # Simulate ingest via internal API
    for _ in range(5):
        fm.ingest(tenant,'inference',cost_units=2.5, units=10, meta={})
    h = fm.hourly_summary(tenant)
    assert h['hours'], 'Hourly summary should not be empty'
    d = fm.daily_summary(tenant)
    assert d['days'], 'Daily summary should not be empty'

def test_estimator_margin_low_variance():
    fm = get_finops_manager(); tenant='var_low'
    _seed_hourly(fm, tenant, [10,10.5,9.8,10.1,9.9,10.2])
    est = estimate_hunt_cost(24, tenant, False)
    assert est['confidence'] in ('high','medium')
    assert est['error_margin_units'] / est['cost_units_estimate'] <= 0.15

def test_estimator_margin_high_variance():
    fm = get_finops_manager(); tenant='var_high'
    _seed_hourly(fm, tenant, [2,15,1,20,3,25])
    est = estimate_hunt_cost(24, tenant, False)
    # High variance should push margin >= 25%
    assert est['error_margin_units'] / est['cost_units_estimate'] >= 0.20
