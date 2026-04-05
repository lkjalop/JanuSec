"""AWS identity/cloud posture detectors (flag-gated).

Looks for common risky patterns in CloudTrail-like payloads.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os


def _enabled() -> bool:
    ff = (os.getenv('FEATURE_FLAGS','') or '')
    return ('feature_iam_domain' in ff) or (os.getenv('ENABLE_IAM_FACTORS','0').lower() in {'1','true','yes'})


def detect_cloud_aws(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    atts: List[Tuple[str,str]] = []
    user = str(payload.get('user') or payload.get('actor') or '')
    resource = str(payload.get('resource') or '')
    etype = str(payload.get('event_type') or payload.get('action') or '').lower()
    raw = dict(payload.get('raw') or {})
    sig = dict(raw.get('signals') or {})

    # Access key created / used without MFA enforcement
    if 'createaccesskey' in etype or sig.get('key_no_mfa') is True:
        f = 'iam:aws_access_key_no_mfa'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))

    # AssumeRole anomaly / privilege chain
    if 'assumerole' in etype or sig.get('assume_role_anomaly') is True:
        f = 'iam:aws_assumerole_anomaly'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))

    # IAM Policy/Role drift
    if ('putrolepolicy' in etype or 'attachrolepolicy' in etype or 'putuserpolicy' in etype) or sig.get('policy_drift') is True:
        f = 'iam:aws_iam_policy_drift'
        factors.append(f)
        if resource:
            atts.append((f'cloud:{resource}', f))

    # Suspicious SSO/OAuth app consent
    if 'sso' in etype and ('oauth' in etype or 'consent' in etype) and (str(raw.get('app_verified') or '').lower() not in {'1','true','yes'}):
        f = 'iam:aws_sso_oauth_suspicious'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))

    return factors, atts

