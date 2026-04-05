from src.analysis.dread_scorer import score_dread


def test_dread_basic():
    factors = {'impact:ransomware': 1.0, 'exfiltration:c2_channel': 0.5}
    out = score_dread(factors)
    # Evidence-based scorer returns structured per-dimension dicts
    assert out['damage']['score_10'] > 0
    assert 0.0 <= out['damage']['score_01'] <= 1.0
    assert 'rationale' in out['damage']
    assert 'evidence' in out['damage']
    assert 'exploitability' in out
    assert 0.0 <= out['exploitability']['score_01'] <= 1.0
    assert 1.0 <= out['composite'] <= 10.0
    assert out['risk_tier'] in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}
    # Legacy 0-1 aliases still present for backward compat
    assert '_damage_01' in out
    assert 0.0 <= out['_damage_01'] <= 1.0
from src.analysis.dread_scorer import score_dread


def test_dread_basic():
    factors = {'impact:ransomware': 1.0, 'exfiltration:c2_channel': 0.5}
    out = score_dread(factors)
    # Evidence-based scorer returns structured per-dimension dicts
    assert out['damage']['score_10'] > 0
    assert 0.0 <= out['damage']['score_01'] <= 1.0
    assert 'rationale' in out['damage']
    assert 'evidence' in out['damage']
    assert 'exploitability' in out
    assert 0.0 <= out['exploitability']['score_01'] <= 1.0
    assert 1.0 <= out['composite'] <= 10.0
    assert out['risk_tier'] in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}
    # Legacy 0-1 aliases still present for backward compat
    assert '_damage_01' in out
    assert 0.0 <= out['_damage_01'] <= 1.0
from core.threat_modeling.factor_taxonomy import compute_dread_score


def test_dread_no_factors():
    res = compute_dread_score([])
    assert 0.0 <= res['risk_score'] <= 1.0


def test_dread_extreme_multipliers():
    res = compute_dread_score(['net:beacon_periodic','ssl:ja3_rare'], asset_criticality=10.0, exposure=10.0)
    # Capped to 1.0
    assert res['risk_score'] <= 1.0
    assert res['risk_score'] >= 0.0

