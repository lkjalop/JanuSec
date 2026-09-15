"""Clean DREAD aggregator (new module).

Use this module to avoid import-time issues caused by a corrupted
`dread_aggregator.py`. It provides the same public function `aggregate`.
"""
from __future__ import annotations

from typing import Dict, Any, Iterable


def _clamp01(v: float) -> float:
    try:
        v = float(v)
    except Exception:
        return 0.0
    if v != v:
        return 0.0
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def aggregate(inputs: Dict[str, Any]) -> Dict[str, float]:
    """Aggregate DREAD components.

    Args:
        inputs: may contain 'cves' (iterable of dict), or 'cvss', 'kev', 'epss',
                plus optional 'anomaly' and 'path_length'.

    Returns a dict with keys: damage, exploit, repro, affected, discover.
    """
    cves = inputs.get('cves') or []
    if cves and isinstance(cves, Iterable):
        cvss = 0.0
        kev = False
        epss = 0.0
        for c in cves:
            if not isinstance(c, dict):
                continue
            try:
                cvss = max(cvss, float(c.get('cvss') or 0.0))
            except Exception:
                pass
            try:
                epss = max(epss, float(c.get('epss') or 0.0))
            except Exception:
                pass
            kev = kev or bool(c.get('kev'))
    else:
        try:
            cvss = float(inputs.get('cvss', 0.0))
        except Exception:
            cvss = 0.0
        kev = bool(inputs.get('kev', False))
        try:
            epss = float(inputs.get('epss', 0.0))
        except Exception:
            epss = 0.0

    try:
        anomaly = float(inputs.get('anomaly', 0.0) or 0.0)
    except Exception:
        anomaly = 0.0
    try:
        path_len = int(inputs.get('path_length', 1) or 1)
    except Exception:
        path_len = 1

    cvss_norm = max(0.0, min(1.0, cvss / 10.0))

    damage = _clamp01(cvss_norm + (0.2 if kev else 0.0))
    exploit = _clamp01(epss * 0.8 + anomaly * 0.5)
    repro = _clamp01(max(0.1, min(1.0, 1.0 / float(max(1, path_len)))))
    affected = _clamp01(min(1.0, 0.4 + cvss_norm * 0.6))
    discover = _clamp01(min(1.0, 0.2 + anomaly * 0.8))

    return {
        'damage': damage,
        'exploit': exploit,
        'repro': repro,
        'affected': affected,
        'discover': discover,
    }
