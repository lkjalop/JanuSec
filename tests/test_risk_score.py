import os
from core.risk_score import compose_risk_score


def test_compose_empty():
    dec = {'factors': [], 'confidence': 0.0}
    out = compose_risk_score(dec)
    assert isinstance(out, dict)
    assert out['score'] == 0.0
    assert out['breakdown'] == []


def test_compose_with_factors_and_confidence():
    dec = {'factors': ['net:beacon_periodic', 'dns:tunnel_suspected'], 'confidence': 0.5}
    out = compose_risk_score(dec)
    assert out['score'] >= 0.0 and out['score'] <= 1.0
    # breakdown entries correspond to factors
    assert len(out['breakdown']) == 2
    # score should be scaled by confidence
    # compute naive expected: multiplicative fusion
    weights = [0.6, 0.45]
    prod = 1.0
    for w in weights:
        prod *= (1.0 - w)
    combined = 1.0 - prod
    expected = combined * 0.5
    assert abs(out['score'] - expected) < 1e-6


def test_env_weights_override(tmp_path, monkeypatch):
    monkeypatch.setenv('RISK_FACTOR_WEIGHTS', 'net:beacon_periodic=0.2,dns:tunnel_suspected=0.1')
    # reload module to pick up env change
    import importlib
    import core.risk_score as rs
    importlib.reload(rs)
    dec = {'factors': ['net:beacon_periodic', 'dns:tunnel_suspected'], 'confidence': 1.0}
    out = rs.compose_risk_score(dec)
    assert len(out['breakdown']) == 2
    weights = [0.2, 0.1]
    prod = 1.0
    for w in weights:
        prod *= (1.0 - w)
    combined = 1.0 - prod
    assert abs(out['score'] - combined) < 1e-6
