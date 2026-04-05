"""Okta identity/cloud detectors (flag-gated).

Emits (factors, attributions) tuples similar to other IAM detectors.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os


def _enabled() -> bool:
    ff = (os.getenv('FEATURE_FLAGS','') or '')
    return ('feature_iam_domain' in ff) or (os.getenv('ENABLE_IAM_FACTORS','0').lower() in {'1','true','yes'})


def detect_identity_okta(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str,str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    atts: List[Tuple[str,str]] = []
    user = str(payload.get('user') or payload.get('actor') or '')
    etype = str(payload.get('event_type') or payload.get('action') or '').lower()
    raw = dict(payload.get('raw') or {})
    sig = dict(raw.get('signals') or {})

    if 'risky_sign_in' in etype or sig.get('risky_sign_in') is True:
        f = 'iam:okta_risky_sign_in'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))

    if 'mfa_policy_drift' in etype or sig.get('mfa_policy_drift') is True:
        f = 'iam:okta_mfa_policy_drift'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))

    if 'oauth_consent' in etype and (str(raw.get('app_verified') or '').lower() not in {'1','true','yes'}):
        f = 'iam:okta_oauth_consent_suspicious'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))

    return factors, atts

