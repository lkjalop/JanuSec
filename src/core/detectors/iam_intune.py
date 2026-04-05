"""Microsoft Intune mini-detectors (flag-gated).

Looks for risky device/compliance policy actions and role assignment changes.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os


def _enabled() -> bool:
    ff = (os.getenv('FEATURE_FLAGS','') or '')
    return ('feature_iam_domain' in ff) or (os.getenv('ENABLE_IAM_FACTORS','0').lower() in {'1','true','yes'})


def detect_intune(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    atts: List[Tuple[str,str]] = []

    user = str(payload.get('user') or payload.get('actor') or '')
    resource = str(payload.get('resource') or '')
    etype = str(payload.get('event_type') or payload.get('action') or '').lower()
    raw = dict(payload.get('raw') or {})
    method = str(raw.get('methodName') or payload.get('method_name') or '').lower()
    sig = dict(raw.get('signals') or {})

    # Compliance policy disabled / device compliance bypass
    if (
        ('compliance' in etype and ('policy' in etype and ('disable' in etype or 'delete' in etype)))
        or ('intune' in method and 'compliance' in method and ('disable' in method or 'delete' in method))
        or sig.get('intune_compliance_disabled') is True
    ):
        f = 'iam:intune_compliance_policy_disabled'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    # Role assignment escalation (Intune RBAC)
    if (
        ('role' in etype and ('assignment' in etype and ('write' in etype or 'create' in etype)))
        or ('intune' in method and 'role' in method and 'assign' in method)
        or sig.get('intune_role_assignment_escalation') is True
    ):
        f = 'iam:intune_role_assignment_escalation'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    return factors, atts

