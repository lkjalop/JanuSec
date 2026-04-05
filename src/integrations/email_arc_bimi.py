from __future__ import annotations
"""ARC/BIMI parsing and simple policy enforcement helpers.

This is a lightweight implementation for demo and tests. It parses common
header forms from 'Authentication-Results', 'ARC-Seal', 'ARC-Message-Signature',
and BIMI indicators.
"""
from typing import Dict, Any


def parse_authentication_results(h: str) -> Dict[str, str]:
    s = (h or '').lower()
    return {
        'dmarc': 'pass' if 'dmarc=pass' in s else ('fail' if 'dmarc=fail' in s else ''),
        'spf': 'pass' if 'spf=pass' in s else ('fail' if 'spf=fail' in s else ''),
        'dkim': 'pass' if 'dkim=pass' in s else ('fail' if 'dkim=fail' in s else ''),
        'arc': 'pass' if 'arc=pass' in s else ('fail' if 'arc=fail' in s else ''),
        'bimi': 'pass' if 'bimi=pass' in s else ('fail' if 'bimi=fail' in s else ''),
    }


def parse_arc(headers: Dict[str, str]) -> str:
    # prefer explicit auth-results arc=
    ar = headers.get('authentication-results', '')
    res = parse_authentication_results(ar).get('arc')
    if res:
        return res
    # fallback: ARC-Seal presence with i= and cv=pass
    seal = (headers.get('arc-seal') or '').lower()
    if 'cv=pass' in seal:
        return 'pass'
    return ''


def parse_bimi(headers: Dict[str, str]) -> str:
    ar = headers.get('authentication-results', '')
    res = parse_authentication_results(ar).get('bimi')
    if res:
        return res
    indicator = (headers.get('bimi-indicator') or headers.get('bimi'))
    if indicator:
        s = str(indicator).lower()
        if 'pass' in s:
            return 'pass'
        if 'fail' in s:
            return 'fail'
    return ''


def enforce_arc_bimi(headers: Dict[str, str]) -> Dict[str, Any]:
    """Return an enforcement suggestion based on ARC/BIMI and DMARC status.

    Policy:
      - If DMARC=fail and ARC=fail -> quarantine
      - If BIMI=fail and DMARC!=pass -> quarantine
      - Else none
    """
    ar = (headers.get('authentication-results') or '')
    auth = parse_authentication_results(ar)
    arc = parse_arc(headers) or auth.get('arc') or ''
    bimi = parse_bimi(headers) or auth.get('bimi') or ''
    action = 'none'
    reasons = []
    if auth.get('dmarc') == 'fail' and arc == 'fail':
        action = 'quarantine'
        reasons.append('arc_fail_with_dmarc_fail')
    elif bimi == 'fail' and auth.get('dmarc') != 'pass':
        action = 'quarantine'
        reasons.append('bimi_fail_weak_dmarc')
    return {
        'enforcement': action,
        'auth': {**auth, 'arc': arc, 'bimi': bimi},
        'factors': [f'email:{r}' for r in reasons],
    }
