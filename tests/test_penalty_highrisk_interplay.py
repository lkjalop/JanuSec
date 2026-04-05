import os, sys, time, pathlib

# Ensure src importable
root = pathlib.Path(__file__).resolve().parents[1]
src = root / 'src'
sp = str(src)
if sp not in sys.path:
    sys.path.insert(0, sp)

from core.risk_score import compose_risk_score


def test_penalty_and_highrisk_interplay(monkeypatch):
    # Set completeness to require 2 classes, penalty 0.5 large enough to affect score
    monkeypatch.setenv('RISK_COMPLETENESS_EXPECTED_CLASSES', 'net,dns')
    monkeypatch.setenv('RISK_COMPLETENESS_MIN_PRESENT', '2')
    monkeypatch.setenv('RISK_COMPLETENESS_PENALTY', '0.5')
    # Base decision with only one class
    dec = {'factors': ['net:one'], 'confidence': 1.0}
    out = compose_risk_score(dec)
    assert any(b['factor'] == 'penalty:incomplete' for b in out['breakdown'])
    base_score = out['score']
    # Now mark high threshold low to inject risk:high meta from final composition
    monkeypatch.setenv('RISK_HIGH_THRESHOLD', '0.1')
    out2 = compose_risk_score(dec)
    # risk:high should be present in breakdown (meta) but not necessarily affect score
    assert any(b['factor'] == 'risk:high' for b in out2['breakdown'])
    # With penalty present, score should be lower or equal
    assert out2['score'] <= base_score
