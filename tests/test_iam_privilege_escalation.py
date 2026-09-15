import pytest
from src.domains.iam.privilege_escalation import (
    detect_assume_role_abuse,
    detect_policy_attachment_to_self,
    detect_adding_user_to_admin_group,
    detect_create_access_key_for_privileged_user,
    detect_permission_boundary_bypass,
    aggregate_iam_findings,
    build_permission_graph_from_state,
    evaluate_lateral_risk,
)


def make_event(eventName, userIdentity=None, requestParameters=None, **extra):
    return {
        'eventName': eventName,
        'userIdentity': userIdentity or {},
        'requestParameters': requestParameters or {},
        **extra,
    }


def test_detect_assume_role_abuse():
    # actor level 3 assumes role level 10 -> flagged
    ev = make_event('AssumeRole', userIdentity={'userName': 'bob'}, requestParameters={'roleArn': 'arn:aws:iam::123:role/admin'}, eventTime=123, actor_permission_level=3, role_permission_level=10)
    findings = detect_assume_role_abuse([ev])
    assert len(findings) == 1
    assert findings[0]['factor'] == 'iam:assume_role_abuse'

    # actor close level -> not flagged
    ev2 = make_event('AssumeRole', userIdentity={'userName': 'alice'}, requestParameters={'roleArn': 'arn'}, actor_permission_level=9, role_permission_level=10)
    findings2 = detect_assume_role_abuse([ev2])
    assert len(findings2) == 0


def test_detect_policy_attachment_to_self():
    ev = make_event('AttachUserPolicy', userIdentity={'userName': 'eve'}, requestParameters={'userName': 'eve', 'policyArn': 'arn:policy'})
    findings = detect_policy_attachment_to_self([ev])
    assert len(findings) == 1
    assert findings[0]['factor'] == 'iam:attach_policy_to_self'

    ev2 = make_event('AttachUserPolicy', userIdentity={'userName': 'admin'}, requestParameters={'userName': 'bob', 'policyArn': 'arn:policy'})
    assert len(detect_policy_attachment_to_self([ev2])) == 0


def test_detect_adding_user_to_admin_group():
    ev = make_event('AddUserToGroup', userIdentity={'userName': 'carl'}, requestParameters={'groupName': 'Administrators', 'userName': 'dave'})
    findings = detect_adding_user_to_admin_group([ev])
    assert len(findings) == 1
    assert findings[0]['factor'] == 'iam:add_user_to_admin_group'

    ev2 = make_event('AddUserToGroup', userIdentity={'userName': 'carl'}, requestParameters={'groupName': 'users', 'userName': 'dave'})
    assert len(detect_adding_user_to_admin_group([ev2])) == 0


def test_detect_create_access_key_for_privileged_user():
    ev = make_event('CreateAccessKey', userIdentity={'userName': 'ops'}, requestParameters={'userName': 'highpriv'}, target_permission_level=9)
    # note: detector reads 'target_permission_level' if present under top-level; include that
    ev['target_permission_level'] = 9
    findings = detect_create_access_key_for_privileged_user([ev])
    assert len(findings) == 1
    assert findings[0]['factor'] == 'iam:create_access_key_privileged'

    ev2 = make_event('CreateAccessKey', userIdentity={'userName': 'ops'}, requestParameters={'userName': 'lowpriv'})
    ev2['target_permission_level'] = 2
    assert len(detect_create_access_key_for_privileged_user([ev2])) == 0


def test_detect_permission_boundary_bypass():
    ev = make_event('PutUserPolicy', userIdentity={'userName': 'attacker'}, requestParameters={'userName': 'victim', 'bypass_permission_boundary': True})
    findings = detect_permission_boundary_bypass([ev])
    assert len(findings) == 1
    assert findings[0]['factor'] == 'iam:permission_boundary_bypass'

    ev2 = make_event('PutUserPolicy', userIdentity={'userName': 'ops'}, requestParameters={'userName': 'victim'})
    assert len(detect_permission_boundary_bypass([ev2])) == 0


def test_aggregate_and_graph():
    events = []
    events.append(make_event('AssumeRole', userIdentity={'userName': 'bob'}, requestParameters={'roleArn': 'r'}, actor_permission_level=3, role_permission_level=10))
    events.append(make_event('AttachUserPolicy', userIdentity={'userName': 'eve'}, requestParameters={'userName': 'eve', 'policyArn': 'p'}))
    events.append(make_event('AddUserToGroup', userIdentity={'userName': 'carl'}, requestParameters={'groupName': 'Administrators', 'userName': 'dave'}))
    agg = aggregate_iam_findings(events)
    assert agg['count'] >= 3

    state = {'user:alice': ['iam:CreateAccessKey', 's3:PutObject'], 'user:ops': ['s3:GetObject']}
    graph = build_permission_graph_from_state(state)
    assert 'user:alice' in graph
    risk = evaluate_lateral_risk(graph)
    assert 'accounts' in risk
