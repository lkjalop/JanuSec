import pytest


def test_compute_bias_basic():
    from src.core.ai_governance.bias_testing import compute_bias

    # Build synthetic decisions with tenant_id and verdict
    decisions = [
        {'tenant_id': 'A', 'verdict': 'malicious'},
        {'tenant_id': 'A', 'verdict': 'benign'},
        {'tenant_id': 'B', 'verdict': 'malicious'},
        {'tenant_id': 'B', 'verdict': 'malicious'},
        {'tenant_id': 'B', 'verdict': 'benign'},
    ]
    res = compute_bias(decisions, 'tenant_id', include_suspicious=False)
    assert res['attribute'] == 'tenant_id'
    # Group A rate = 0.5 (1/2), Group B rate = 0.6667 (2/3)
    rates = {g['group']: g['positive_rate'] for g in res['groups']}
    assert pytest.approx(rates['A'], 0.01) == 0.5
    assert pytest.approx(rates['B'], 0.01) == 0.6667
    # DIR = min/max
    assert res['dir'] <= 1.0
    # EOD approx
    assert res['eod'] >= 0.0

