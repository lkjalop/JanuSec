import pytest
from datetime import datetime

from src.schemas.email import NormalizedEmailEvent
from src.detection.supply_chain_rules import DeveloperTargetedPhishing


def test_calculate_supply_chain_risk_basic():
    e = NormalizedEmailEvent(
        sender='attacker@phish.example',
        recipient='alice@acme.com',
        subject='Please update your npm package',
        targets_developer=True,
        references_package_registry=True,
        references_code_platform=True,
        references_cicd=False,
        oauth_consent_attempted=False,
        raw_event={'spf_result': 'pass', 'dmarc_result': 'pass'}
    )
    score = e.calculate_supply_chain_risk()
    assert score > 0.5


def test_developer_targeted_phishing_rule():
    e = NormalizedEmailEvent(
        sender='spoof@github.com',
        recipient='devops@acme.com',
        subject='GitHub action requires token',
        body_preview='Please grant OAuth permission to repo write',
        targets_developer=True
    )
    rule = DeveloperTargetedPhishing()
    m = rule.evaluate(e)
    assert m is not None
    assert 'developer' in m.description.lower() or m.severity in ('HIGH','CRITICAL')
