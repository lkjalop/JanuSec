from __future__ import annotations
from typing import Any, Dict, List

PRODUCER = 'iam_privilege_escalation'

_HIGH_RISK = {
    'CreateAccessKey',
    'AttachUserPolicy',
    'PutUserPolicy',
    'AttachRolePolicy',
    'PassRole',
    'UpdateAssumeRolePolicy',
    'AddUserToGroup',
    'PutRolePolicy',
}

_ADMIN_POLICIES = {'AdministratorAccess','PowerUserAccess'}
_CONSOLE_EVENTS = {'ConsoleLogin','SwitchRole','AssumeRole','UpdateLoginProfile'}
_SUSPICIOUS_API = {'CreateUser','CreateAccessKey','CreateLoginProfile','AttachUserPolicy','AttachRolePolicy','PassRole','AddUserToGroup'}


def _lower(x: Any) -> str:
    try:
        return str(x or '').lower()
    except Exception:
        return ''


def detect_privilege_escalation(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    events = list(getattr(runtime, 'sanitized_events', []) or [])
    for ev in events:
        svc = _lower(ev.get('eventSource') or ev.get('service'))
        name = str(ev.get('eventName') or ev.get('action') or '')
        if not svc and not name:
            continue
        if 'iam' not in svc and name not in _HIGH_RISK and name not in _CONSOLE_EVENTS and name not in _SUSPICIOUS_API:
            continue
        # policy context
        pol = str(ev.get('policy') or ev.get('policyName') or '')
        group = str(ev.get('groupName') or '')
        user = str(ev.get('userName') or ev.get('user') or '')
        score = 0.65
        rationale = []
        if name in _HIGH_RISK:
            score = max(score, 0.8); rationale.append('high_risk_api')
        if pol in _ADMIN_POLICIES:
            score = max(score, 0.9); rationale.append('admin_policy_attached')
        if name in _CONSOLE_EVENTS:
            score = max(score, 0.75); rationale.append('console_elevation_event')
        if name in _SUSPICIOUS_API:
            score = max(score, 0.7); rationale.append('suspicious_api_call')
        # role change context
        role = str(ev.get('role') or ev.get('roleName') or ev.get('assumedRole') or '')
        if role:
            rationale.append('role_change')
        out.append({'factor':'iam_privilege_escalation','score':score,'producer':PRODUCER,'eventName':name or None,'policy':pol or None,'group':group or None,'user': user or None,'role': role or None,'reason': ','.join(rationale) if rationale else None})
    return out

__all__ = ['detect_privilege_escalation']
