from __future__ import annotations
from typing import Dict, Any, List

PRODUCER = 'cloudtrail_risk_scoring'

_EVENT_WEIGHTS = {
    'CreateAccessKey': 0.85,
    'AttachUserPolicy': 0.8,
    'PutUserPolicy': 0.8,
    'AttachRolePolicy': 0.78,
    'PassRole': 0.88,
    'UpdateAssumeRolePolicy': 0.86,
    'AddUserToGroup': 0.72,
    'PutRolePolicy': 0.8,
    'CreateLoginProfile': 0.82,
}

_DEF_ALT = 0.6


def score_cloudtrail_events(runtime) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if runtime is None:
        return out
    events = list(getattr(runtime, 'sanitized_events', []) or [])
    for ev in events:
        name = str(ev.get('eventName') or ev.get('action') or '')
        if not name:
            continue
        s = float(_EVENT_WEIGHTS.get(name, _DEF_ALT))
        src_ip = ev.get('sourceIPAddress') or ev.get('source_ip')
        user = ev.get('userName') or ev.get('user')
        out.append({'factor':'cloudtrail_high_risk','score':s,'producer':PRODUCER,'eventName':name,'user':user,'source_ip':src_ip})
    return out

__all__ = ['score_cloudtrail_events']
