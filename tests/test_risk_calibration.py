import os
import json
from core.risk_score import compose_risk_score


def test_triage_score_present_and_bounds():
    dec = {'factors': ['scenario:high_cred', 'endpoint:weird_proc'], 'confidence': 0.9}
    out = compose_risk_score(dec)
    assert isinstance(out, dict)
    assert 'triage_score' in out
    ts = float(out['triage_score'])
    assert 0.0 <= ts <= 1.0


def test_verdict_calibration_reduces_low_diversity(monkeypatch):
    # Enable calibration and set min diversity high to trigger reduction
    monkeypatch.setenv('RISK_VERDICT_CALIBRATION_ENABLED', '1')
    monkeypatch.setenv('RISK_VERDICT_MIN_DIVERSITY', '3')
    dec = {'factors': ['scenario:high_cred', 'scenario:low_impact'], 'confidence': 1.0}
    out = compose_risk_score(dec)
    assert isinstance(out, dict)
    assert out.get('calibrated') is True
    assert 'calibration_reason' in out
    # score should be reduced relative to triage_score or raw_score
    s = float(out.get('score') or 0.0)
    tri = float(out.get('triage_score') or 0.0)
    assert s <= tri


def test_verdict_no_calibration_when_disabled(monkeypatch):
    monkeypatch.setenv('RISK_VERDICT_CALIBRATION_ENABLED', '0')
    dec = {'factors': ['scenario:high_cred'], 'confidence': 1.0}
    out = compose_risk_score(dec)
    assert out.get('calibrated') in (False, None)
