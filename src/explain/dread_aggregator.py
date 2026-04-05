
"""Aggregation helpers for DREAD-like scoring.

Provides two functions:
- `deterministic_aggregate(records)` — deterministic mapping from record batches
- `dread_aggregate(inputs)` — computes DREAD components from CVE/EPSS/anomaly inputs
"""
from __future__ import annotations

from typing import Iterable, Dict, Any
import hashlib


def _score_from_hash(s: str, scale: float = 10.0) -> float:
    h = hashlib.sha256(s.encode('utf-8')).digest()
    v = h[0] / 255.0
    return round(v * scale, 3)


def deterministic_aggregate(records: Iterable[Dict[str, Any]]) -> Dict[str, float]:
    parts = []
    count = 0
    for r in records:
        count += 1
        user = r.get('user') or r.get('username') or ''
        host = r.get('host') or r.get('hostname') or ''
        ip = r.get('ip') or r.get('src_ip') or r.get('ip_src') or ''
        fn = r.get('file_name') or r.get('process') or ''
        parts.append(f"{user}|{host}|{ip}|{fn}")
    base = '|'.join(parts) or 'empty'
    damage = _score_from_hash('damage|' + base)
    reproducibility = _score_from_hash('repro|' + base)
    exploitability = _score_from_hash('exploit|' + base)
    affected = _score_from_hash('affected|' + base)
    discoverability = _score_from_hash('discover|' + base)

    bias = min(1.0, max(0.0, count / 100.0))

    def _apply_bias(v: float) -> float:
        return round(min(10.0, v * (1.0 + 0.15 * bias)), 3)

    return {
        'damage': _apply_bias(damage),
        'repro': _apply_bias(reproducibility),
        'exploit': _apply_bias(exploitability),
        'affected': _apply_bias(affected),
        'discover': _apply_bias(discoverability),
    }


def _clamp01(v: float) -> float:
    try:
        return max(0.0, min(1.0, float(v)))
    except Exception:
        return 0.0


def dread_aggregate(inputs: Dict[str, Any]) -> Dict[str, float]:
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


# Backwards-compatible default
aggregate = dread_aggregate

__all__ = ['deterministic_aggregate', 'dread_aggregate', 'aggregate']


