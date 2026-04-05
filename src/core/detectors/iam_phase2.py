"""IAM Phase 2 detectors (token/GPO/impossible travel/stuffing/honeypot).

All detectors are guarded by the same IAM feature flags used in iam_critical.
They return (factors, attributions) where attributions are (node_id, factor)
pairs that callers can use to enrich HopGraph.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os


def _enabled() -> bool:
    ff = (os.getenv('FEATURE_FLAGS','') or '')
    return ('feature_iam_domain' in ff) or (os.getenv('ENABLE_IAM_FACTORS','0').lower() in {'1','true','yes'})


def _is_modify(op: str) -> bool:
    o = (op or '').lower()
    return any(k in o for k in ('modify','change','update','write','add','set'))


def detect_identity_phase2(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    attrs: List[Tuple[str, str]] = []
    user = str(payload.get('user') or payload.get('actor') or '')
    event_type = str(payload.get('event_type') or payload.get('operation') or payload.get('action') or '').lower()
    obj = str(payload.get('object') or payload.get('dn') or payload.get('path') or '').lower()

    # Token manipulation / impersonation
    if ('token' in event_type and ('imperson' in event_type or 'manip' in event_type)) or payload.get('action') == 'token_impersonation':
        f = 'iam:token_manipulation'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    # GPO modification linked to privilege escalation
    if (('gpo' in obj) or ('group policy' in obj) or ('policies' in obj)) and _is_modify(event_type):
        f = 'iam:gpo_modification_privilege_escalation'
        factors.append(f)
        attrs.append(('ad:gpo', f))
        if user:
            attrs.append((f'user:{user}', f))

    # Credential stuffing success
    try:
        failed_count = int(payload.get('failed_login_count') or payload.get('auth',{}).get('failed_count') or 0)
    except Exception:
        failed_count = 0
    success = str(payload.get('result') or payload.get('auth',{}).get('result') or '').lower() == 'success'
    if (failed_count >= 5 and success) or (str(payload.get('event') or '').lower() == 'credential_stuffing_success'):
        f = 'iam:credential_stuffing_success'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))

    # Honeypot account access
    hp_env = (os.getenv('HONEYPOT_USERS','') or '')
    honeypots = {u.strip().lower() for u in hp_env.split(',') if u.strip()}
    if user and honeypots and user.lower() in honeypots:
        f = 'iam:honeypot_account_access'
        factors.append(f)
        attrs.append((f'user:{user}', f))

    return factors, attrs


def detect_remote_access_phase2(event: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    if not _enabled():
        return [], []
    factors: List[str] = []
    attrs: List[Tuple[str, str]] = []
    raw = dict(event.get('raw') or {})
    user = str(event.get('user') or raw.get('user') or '')
    host = str(event.get('dest_host') or raw.get('dest_host') or '')
    signals = dict(raw.get('signals') or {})
    if signals.get('impossible_travel') is True:
        f = 'iam:impossible_travel'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))
        if host:
            attrs.append((f'host:{host}', f))
    return factors, attrs

