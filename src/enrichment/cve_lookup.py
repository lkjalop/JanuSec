"""Minimal CVE / OSV lookup + scoring stub.

Provides cached lookup functions; in offline/demo mode returns synthetic data
to drive vulnerability factors (vuln:cvss_critical) without external calls.
"""
from __future__ import annotations

import os, time
from typing import Dict, Any, Optional

_CACHE: Dict[str, Dict[str, Any]] = {}

def _synth_record(cve: str) -> Dict[str, Any]:
    # Simple synthetic heuristic: last digit influences CVSS
    try:
        tail = int(cve.split('-')[-1])
    except Exception:
        tail = 0
    base = 9.3 if tail % 7 == 0 else (8.1 if tail % 5 == 0 else 6.4)
    return {
        'cve': cve,
        'cvss_base_score': base,
        'vector': 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' if base >= 9.0 else 'AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N',
        'fetched_ts': time.time(),
        'source': 'synthetic',
    }

def lookup_cve(cve: str, *, use_network: bool | None = None) -> Optional[Dict[str, Any]]:
    cve = cve.upper().strip()
    if not cve.startswith('CVE-'):
        return None
    if cve in _CACHE:
        return _CACHE[cve]
    # Demo: skip real network unless explicitly requested and allowed
    if use_network and os.getenv('ENABLE_REAL_CVE_LOOKUP','0') in {'1','true','yes'}:
        # Placeholder for future network call integration
        pass
    rec = _synth_record(cve)
    _CACHE[cve] = rec
    return rec

def vulnerability_factors_for(rec: Dict[str, Any]) -> list[str]:
    fs: list[str] = []
    try:
        score = float(rec.get('cvss_base_score') or 0.0)
        if score >= 9.0:
            fs.append('vuln:cvss_critical')
    except Exception:
        pass
    return fs

__all__ = ['lookup_cve','vulnerability_factors_for']