"""AWS CloudTrail high-risk event scoring helpers.

Simple heuristics for certain event names with contextual scoring.
"""
from typing import Dict, Any


HIGH_RISK = {
    'DeleteTrail': 1.0,
    'StopLogging': 1.0,
    'PutBucketPolicy': 0.8,
    'PutBucketAcl': 0.8,
    'CreateAccessKey': 0.85,
    'PutUserPolicy': 0.9,
}


def score_cloud_event(event: Dict[str, Any]) -> Dict[str, Any]:
    name = event.get('eventName')
    base = HIGH_RISK.get(name, 0.0)
    adjustments = 0.0
    reasons = []

    # root usage
    user = event.get('userIdentity') or {}
    if user.get('type') == 'Root':
        adjustments += 0.4
        reasons.append('root_account')

    src = event.get('sourceIPAddress')
    if src and not src.startswith('10.') and not src.startswith('192.168.'):
        adjustments += 0.1
        reasons.append('public_source')

    # public bucket exposure
    if name in ('PutBucketPolicy','PutBucketAcl') and event.get('requestParameters', {}).get('acl') == 'public-read':
        adjustments += 0.35
        reasons.append('public_bucket')

    score = min(1.0, base + adjustments)
    return {'score': score, 'reasons': reasons, 'base': base}


__all__ = ['score_cloud_event']
