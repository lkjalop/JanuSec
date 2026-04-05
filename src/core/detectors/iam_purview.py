"""Microsoft Purview mini-detectors (flag-gated).

Looks for data governance control disablement and sensitivity/classification drift.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os


def _enabled() -> bool:
    ff = (os.getenv('FEATURE_FLAGS','') or '')
    return ('feature_iam_domain' in ff) or (os.getenv('ENABLE_IAM_FACTORS','0').lower() in {'1','true','yes'})


def detect_purview(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
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

    # Scan policy disabled / paused unexpectedly
    if (
        ('purview' in etype and 'scan' in etype and ('disable' in etype or 'pause' in etype))
        or ('purview' in method and 'scan' in method and ('disable' in method or 'pause' in method))
        or sig.get('purview_scan_policy_disabled') is True
    ):
        f = 'iam:purview_scan_policy_disabled'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    # Sensitivity label/classification rule drift (weak heuristic)
    if (
        ('purview' in etype and ('sensitivity' in etype or 'classification' in etype) and ('change' in etype or 'update' in etype))
        or ('purview' in method and ('sensitivity' in method or 'classification' in method) and ('update' in method or 'set' in method))
        or sig.get('purview_sensitivity_label_drift') is True
    ):
        f = 'iam:purview_sensitivity_label_drift'
        factors.append(f)
        if user:
            atts.append((f'user:{user}', f))
        if resource:
            atts.append((f'cloud:{resource}', f))

    return factors, atts

