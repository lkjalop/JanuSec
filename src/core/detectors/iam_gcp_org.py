"""GCP Organization/Admin risky IAM operations (flag-gated).

Detects org-level IAM setIamPolicy, high-risk Service Usage enablement,
and disabling orgpolicy constraints.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os


def _enabled() -> bool:
    ff = (os.getenv('FEATURE_FLAGS','') or '')
    return ('feature_iam_domain' in ff) or (os.getenv('ENABLE_IAM_FACTORS','0').lower() in {'1','true','yes'})


def detect_cloud_gcp_org(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    atts: List[Tuple[str,str]] = []

    user = str(payload.get('user') or payload.get('actor') or '')
    resource = str(payload.get('resource') or '')
    etype = str(payload.get('event_type') or payload.get('action') or '').lower()
    raw = dict(payload.get('raw') or {})
    sig = dict(raw.get('signals') or {})
    method = str(raw.get('methodName') or payload.get('method_name') or '').lower()

    # setIamPolicy at organization scope
    if (
        'setiampolicy' in etype and (resource.startswith('organizations/') or sig.get('org_scope') is True)
        or 'resourcemanager.organizations.setiampolicy' in method
        or 'cloudresourcemanager.organizations.setiampolicy' in method
        or sig.get('org_setiampolicy') is True
    ):
        f = 'iam:gcp_setIamPolicy_org_escalation'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    # Service Usage high-risk API enablement
    if (
        ('serviceusage' in etype and 'enable' in etype)
        or 'serviceusage.services.enable' in method
        or sig.get('high_risk_api_enable') is True
    ):
        f = 'iam:gcp_serviceusage_high_risk_enable'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    # OrgPolicy constraint disable
    if (
        ('orgpolicy' in etype and ('constraint' in etype or 'constraints' in etype) and ('disable' in etype or 'delete' in etype))
        or ('orgpolicy' in method and ('constraint' in method or 'constraints' in method) and ('disable' in method or 'delete' in method))
        or sig.get('orgpolicy_constraint_disable') is True
    ):
        f = 'iam:gcp_orgpolicy_constraint_disable'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    return factors, atts
