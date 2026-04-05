"""Critical IAM detectors (Phase 1) guarded by feature flags.

Factors implemented (heuristic/minimal):
 - iam:ntds_dit_access
 - iam:lsass_memory_read_unusual_process
 - iam:skeleton_key_attack
 - iam:dc_shadow
 - iam:adminSDHolder_modification

All functions are best-effort and safe when required fields are missing.
Attribution is returned as (node_id, factor) pairs so callers can attach to
HopGraph nodes when available.
"""
from __future__ import annotations
from typing import Dict, Any, List, Tuple
import os


def _enabled() -> bool:
    ff = (os.getenv('FEATURE_FLAGS','') or '')
    return ('feature_iam_domain' in ff) or (os.getenv('ENABLE_IAM_FACTORS','0').lower() in {'1','true','yes'})


def detect_endpoint(event: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Detect endpoint-side IAM critical behaviors from a single event.

    Returns (factors, attributions) where attributions is list of (node_id, factor).
    """
    if not _enabled():
        return [], []
    factors: List[str] = []
    attrs: List[Tuple[str, str]] = []
    host = (event.get('host') or '')
    proc = ''
    try:
        p = event.get('process') or {}
        proc = (p.get('name') or '')
    except Exception:
        proc = ''
    cmd = ''
    try:
        cmd = (event.get('process') or {}).get('command') or event.get('command') or ''
    except Exception:
        cmd = ''
    # Heuristic: LSASS memory reads / handle open attempts
    low = (cmd or '').lower()
    if ('lsass' in low) and not any(x in low for x in ('procdump.exe', 'taskmgr.exe', 'dbgview.exe')):
        f = 'iam:lsass_memory_read_unusual_process'
        factors.append(f)
        if host:
            attrs.append((f'host:{host}', f))
        if proc:
            attrs.append((f'process:{proc}', f))
    # Heuristic: NTDS.dit access on DCs (path mention in command or file field)
    path = (event.get('file') or event.get('path') or '')
    plow = str(path).lower()
    if ('\\ntds\\ntds.dit' in plow) or ('\\windows\\ntds\\ntds.dit' in plow) or ('ntds.dit' in low):
        f = 'iam:ntds_dit_access'
        factors.append(f)
        if host:
            attrs.append((f'host:{host}', f))
        attrs.append(('resource:ntds.dit', f))
    # Heuristic: Skeleton key hints (write to LSASS modules or known strings)
    if ('skeleton' in low and 'key' in low) or ('patch' in low and 'lsass' in low):
        f = 'iam:skeleton_key_attack'
        factors.append(f)
        if host:
            attrs.append((f'host:{host}', f))
        if proc:
            attrs.append((f'process:{proc}', f))
    return factors, attrs


def detect_identity(payload: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Detect directory-side IAM critical events (AD/AAD logs)."""
    if not _enabled():
        return [], []
    factors: List[str] = []
    attrs: List[Tuple[str, str]] = []
    etype = (payload.get('event_type') or payload.get('operation') or '').lower()
    obj = (payload.get('object') or payload.get('dn') or payload.get('path') or '').lower()
    user = (payload.get('user') or payload.get('actor') or '')
    # DCShadow indicator: new DC registration / replication metadata spoof
    if ('dcshadow' in etype) or ('dc shadow' in etype) or ('rogue dc' in etype) or ('ntds settings' in obj and 'add' in etype):
        f = 'iam:dc_shadow'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))
        attrs.append(('ad:dc', f))
    # adminSDHolder modification
    if ('adminsdholder' in obj) and any(k in etype for k in ('modify','change','update','write')):
        f = 'iam:adminSDHolder_modification'
        factors.append(f)
        if user:
            attrs.append((f'user:{user}', f))
        attrs.append(('ad:adminsdholder', f))
    return factors, attrs

