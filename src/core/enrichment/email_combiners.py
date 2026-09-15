"""Helpers to combine email auth signals and reputation into a unified enrichment
and provide sub-score breakdown for DREAD adjustments and escalation rationale.

This module provides deterministic, dependency-free functions suitable for
unit testing and demo mode. Production integrations should replace or extend
these with real SPF/DMARC/ARC verification and external reputation lookups.
"""
from typing import Dict, Any
import time


def combine_email_signals(auth: Dict[str, Any], headers: Dict[str, Any], envelope: Dict[str, Any], reputations: Dict[str, float] | None = None) -> Dict[str, Any]:
    """Combine DKIM/SPF/DMARC/ARC flags, header-forensics, envelope mismatches,
    and reputation multipliers into a unified enrichment payload.

    Inputs are permissive dicts; missing keys are treated conservatively.
    Returns a dict with normalized boolean flags, confidence multipliers, and
    a human-friendly `why` rationale plus evidence links placeholders.
    """
    reputations = reputations or {}
    dkim = (auth or {}).get('dkim')
    spf = (auth or {}).get('spf')
    dmarc = (auth or {}).get('dmarc')
    arc = (auth or {}).get('arc')

    # Normalized booleans
    ok_dkim = bool(dkim == 'pass' or dkim is True)
    ok_spf = bool(spf == 'pass' or spf is True)
    ok_dmarc = bool(dmarc == 'pass' or dmarc is True)
    ok_arc = bool(arc == 'pass' or arc is True)

    # Header-forensics: Return-Path vs From mismatch
    from_addr = (headers or {}).get('From') or (headers or {}).get('from')
    return_path = (envelope or {}).get('return_path') or (envelope or {}).get('mailfrom')
    header_mismatch = False
    if from_addr and return_path:
        try:
            # simple domain compare
            from_dom = from_addr.split('@')[-1].lower().strip() if '@' in from_addr else from_addr.lower().strip()
            rp_dom = return_path.split('@')[-1].lower().strip() if '@' in return_path else return_path.lower().strip()
            header_mismatch = from_dom != rp_dom
        except Exception:
            header_mismatch = False

    # Compute a base confidence multiplier from auth chain
    # Start neutral (1.0), reduce toward 0.5 for failures, increase to 1.2 for multiple passes
    multiplier = 1.0
    passed = sum([ok_dkim, ok_spf, ok_dmarc, ok_arc])
    if passed >= 3:
        multiplier *= 1.15
    elif passed == 2:
        multiplier *= 1.0
    elif passed == 1:
        multiplier *= 0.85
    else:
        multiplier *= 0.6

    # Header mismatch and envelope anomalies reduce confidence
    if header_mismatch:
        multiplier *= 0.7

    # Apply reputations (each reputation is expected as a multiplier around 0.5-1.5)
    rep_effect = 1.0
    for k, v in (reputations or {}).items():
        try:
            rep_effect *= float(v)
        except Exception:
            continue
    multiplier *= rep_effect

    # Bound multiplier
    multiplier = max(0.25, min(2.0, multiplier))

    why = []
    why.append(f"dkim={'pass' if ok_dkim else 'fail' if dkim else 'unknown'}")
    why.append(f"spf={'pass' if ok_spf else 'fail' if spf else 'unknown'}")
    why.append(f"dmarc={'pass' if ok_dmarc else 'fail' if dmarc else 'unknown'}")
    if header_mismatch:
        why.append('header_returnpath_mismatch')
    if reputations:
        why.append('reputation_applied')

    evidence = {
        'dkim_record': (auth or {}).get('dkim_record'),
        'spf_record': (auth or {}).get('spf_record'),
        'dmarc_record': (auth or {}).get('dmarc_record'),
        'envelope': envelope,
        'headers': {k: headers.get(k) for k in ('From', 'Return-Path', 'Subject') if headers and headers.get(k)} if headers else {},
    }

    return {
        'timestamp': int(time.time()),
        'ok_dkim': ok_dkim,
        'ok_spf': ok_spf,
        'ok_dmarc': ok_dmarc,
        'ok_arc': ok_arc,
        'header_mismatch': header_mismatch,
        'multiplier': multiplier,
        'reputation_effect': rep_effect,
        'why': '; '.join(why),
        'evidence': evidence,
    }
