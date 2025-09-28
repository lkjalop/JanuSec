"""Severity Rollup Stub

Provides a minimal snapshot() returning empty or baseline rollup data so that
imports from core.metrics.severity_rollup succeed during test collection even
if a richer implementation is pending.
"""
from __future__ import annotations
from typing import Dict, Any
import time

_DEF_BASE = {
    'buckets': {'low':0,'medium':0,'high':0,'critical':0},
    'updated_ts': lambda: int(time.time())
}

_last: Dict[str, Any] | None = None

def observe(severity: float | int):  # simplistic bucket accounting
    global _last
    if _last is None:
        _last = { 'buckets': {'low':0,'medium':0,'high':0,'critical':0}, 'updated_ts': int(time.time()) }
    s = float(severity)
    if s < 0.3: key = 'low'
    elif s < 0.6: key = 'medium'
    elif s < 0.85: key = 'high'
    else: key = 'critical'
    _last['buckets'][key] += 1
    _last['updated_ts'] = int(time.time())


def snapshot() -> Dict[str, Any]:
    global _last
    if _last is None:
        return { 'buckets': {'low':0,'medium':0,'high':0,'critical':0}, 'updated_ts': int(time.time()) }
    return _last.copy()
