import pytest

from src.core.detectors.iam_priv_escalation import detect_privilege_escalation


class _Runtime:
    def __init__(self, events):
        self.sanitized_events = events


def test_iam_console_elevation_and_role_change():
    rt = _Runtime([
        {'eventSource': 'iam.amazonaws.com', 'eventName': 'SwitchRole', 'userName': 'alice', 'roleName': 'AdminRole'},
        {'eventSource': 'iam.amazonaws.com', 'eventName': 'AttachUserPolicy', 'userName': 'bob', 'policyName': 'AdministratorAccess'},
    ])
    res = detect_privilege_escalation(rt)
    assert any(r.get('factor') == 'iam_privilege_escalation' and r.get('role') == 'AdminRole' for r in res)
    # Admin policy attachment should have higher score
    scores = [r.get('score') for r in res]
    assert max(scores) >= 0.9


def test_iam_suspicious_api_calls():
    rt = _Runtime([
        {'eventSource': 'iam.amazonaws.com', 'eventName': 'CreateAccessKey', 'userName': 'charlie'},
        {'eventSource': 'iam.amazonaws.com', 'eventName': 'AddUserToGroup', 'userName': 'dave', 'groupName': 'admins'},
    ])
    res = detect_privilege_escalation(rt)
    assert len(res) >= 2
    assert all(r.get('factor') == 'iam_privilege_escalation' for r in res)
    assert any('suspicious_api_call' in (r.get('reason') or '') for r in res)
