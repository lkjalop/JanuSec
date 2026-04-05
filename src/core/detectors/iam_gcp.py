"""GCP identity/cloud detectors (flag-gated).

Detects common risky IAM-related patterns in GCP audit-like payloads.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os


def _enabled() -> bool:
    ff = (os.getenv('FEATURE_FLAGS','') or '')
    return ('feature_iam_domain' in ff) or (os.getenv('ENABLE_IAM_FACTORS','0').lower() in {'1','true','yes'})


def detect_cloud_gcp(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    atts: List[Tuple[str, str]] = []

    user = str(payload.get('user') or payload.get('actor') or '')
    resource = str(payload.get('resource') or '')
    etype = str(payload.get('event_type') or payload.get('action') or '').lower()
    raw = dict(payload.get('raw') or {})
    sig = dict(raw.get('signals') or {})

    # Service Account key creation storm / creation events
    if (
        ('serviceaccount' in etype and ('key' in etype or 'keys' in etype or 'create' in etype))
        or sig.get('sa_key_storm') is True
        or sig.get('service_account_key_created') is True
    ):
        f = 'iam:gcp_service_account_key_storm'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    # Organization Policy bypass
    if (
        ('orgpolicy' in etype and ('bypass' in etype or 'override' in etype))
        or sig.get('org_policy_bypass') is True
    ):
        f = 'iam:gcp_org_policy_bypass'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    # Workload Identity abuse
    if (
        ('workload' in etype and 'identity' in etype)
        or sig.get('workload_identity_abuse') is True
    ):
        f = 'iam:gcp_workload_identity_abuse'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    return factors, atts

