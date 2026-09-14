import pytest
from src.core.log_schema import make_event, validate_event
from src.core.evidence_model import EvidenceItem, BayesianFusion


def test_make_and_validate_event():
    e = make_event("tenant-a", "aws_cloudtrail", "aws_cloudtrail", "cloud", ip="10.0.0.1")
    ok, errors = validate_event(e)
    assert ok, f"event should validate, errors={errors}"


def test_validate_bad_event():
    bad = {"tenant_id": 123}
    ok, errors = validate_event(bad)
    assert not ok
    assert any("missing required key" in e for e in errors)


def test_bayesian_fusion_simple():
    bf = BayesianFusion()
    evidence = [
        EvidenceItem(kind="heartbeat_zero", score=2.0),
        EvidenceItem(kind="collector_crash", score=3.0),
    ]

    hs = bf.score("collector_failure", evidence)
    # both positive LLRs should give high probability
    assert hs.probability > 0.95
    assert hs.hypothesis == "collector_failure"


def test_bayesian_fusion_prior():
    bf = BayesianFusion(prior_odds={"auth_issue": 0.1})
    evidence = [EvidenceItem(kind="api_401", score=1.2)]
    hs = bf.score("auth_issue", evidence)
    assert 0.1 < hs.probability < 0.9
