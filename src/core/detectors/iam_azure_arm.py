"""Azure Resource Manager (ARM) IAM/admin detectors (flag-gated).

Detects risky role/policy/lock operations from Azure Activity Log-like payloads.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os


def _enabled() -> bool:
    ff = (os.getenv('FEATURE_FLAGS','') or '')
    return ('feature_iam_domain' in ff) or (os.getenv('ENABLE_IAM_FACTORS','0').lower() in {'1','true','yes'})


def detect_cloud_azure(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    atts: List[Tuple[str,str]] = []

    user = str(payload.get('user') or payload.get('actor') or payload.get('caller') or '')
    resource = str(payload.get('resource') or '')
    etype = str(payload.get('event_type') or payload.get('action') or '').lower()
    raw = dict(payload.get('raw') or {})
    sig = dict(raw.get('signals') or {})
    op = str(payload.get('operation_name') or raw.get('operationName') or raw.get('methodName') or '').lower()

    # Role/Policy set (policy or assignment modification) -> potential escalation
    # Match common ARM operations and a generic risk signal
    if (
        'microsoft.authorization/roleassignments/write' in etype
        or 'microsoft.authorization/roledefinitions/write' in etype
        or 'microsoft.authorization/policyassignments/write' in etype
        or ('policyassignment' in etype and ('write' in etype or 'create' in etype))
        or 'microsoft.authorization/roleassignments/write' in op
        or 'microsoft.authorization/roledefinitions/write' in op
        or 'microsoft.authorization/policyassignments/write' in op
        or sig.get('setiam_policy') is True
    ):
        f = 'iam:azure_arm_setiam_policy_escalation'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    # Custom role privilege escalation indicators
    if (
        'customrole' in etype or 'roledefinitions' in etype or 'custom role' in etype
        or 'roledefinitions' in op or 'customrole' in op
        or sig.get('custom_role_priv_escalation') is True
    ):
        f = 'iam:azure_arm_custom_role_priv_escalation'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    # Resource lock bypass: removing or disabling resource locks
    if (
        'microsoft.authorization/locks/delete' in etype
        or 'microsoft.authorization/locks/delete' in op
        or ('resource_lock' in etype and ('delete' in etype or 'bypass' in etype))
        or sig.get('resource_lock_bypass') is True
    ):
        f = 'iam:azure_resource_lock_bypass'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    return factors, atts
