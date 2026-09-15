"""ASN frequency tracking for rarity scoring with optional decay.

Decay model: every DECAY_INTERVAL seconds, multiply all counts by DECAY_FACTOR (0<factor<=1).
Env vars:
    ASN_DECAY_INTERVAL_SECONDS (default 0 -> disabled)
    ASN_DECAY_FACTOR (default 0.9)
Metrics (best-effort):
    asn_distinct_current
    asn_decay_runs_total
"""
from __future__ import annotations

import os
import threading
import time
from typing import Dict

_TTL = int(__import__('os').getenv('ASN_FREQ_TTL_SECONDS','3600'))
_lock = threading.Lock()
_asn_counts: dict[str, dict] = {}
_total = 0
_DECAY_INTERVAL = int(os.getenv('ASN_DECAY_INTERVAL_SECONDS','0'))
_DECAY_FACTOR = float(os.getenv('ASN_DECAY_FACTOR','0.9'))
_LAST_DECAY = time.time()

try:  # pragma: no cover
    from prometheus_client import Counter as _C, Gauge as _G  # type: ignore
    _asn_distinct_gauge = _G('asn_distinct_current','Current distinct ASNs tracked')  # type: ignore
    _asn_decay_runs = _C('asn_decay_runs_total','ASN decay applications')  # type: ignore
except Exception:  # pragma: no cover
    class _Stub:
        def set(self,*a,**k): return None
        def inc(self,*a,**k): return None
    _asn_distinct_gauge = _Stub(); _asn_decay_runs = _Stub()

def _maybe_decay(now: float):
    global _LAST_DECAY
    if _DECAY_INTERVAL <= 0:
        return
    if now - _LAST_DECAY < _DECAY_INTERVAL:
        return
    # Apply decay
    for a, rec in list(_asn_counts.items()):
        rec['c'] *= _DECAY_FACTOR
        # Prune near-zero counts
        if rec['c'] < 0.5:
            _asn_counts.pop(a, None)
    _LAST_DECAY = now
    try: _asn_decay_runs.inc()  # type: ignore
    except Exception: pass
    try: _asn_distinct_gauge.set(len(_asn_counts))  # type: ignore
    except Exception: pass

def record(asn: str | None):
    global _total
    if not asn:
        return
    now = time.time()
    with _lock:
        _maybe_decay(now)
        rec = _asn_counts.get(asn)
        if not rec:
            rec = {'c':0,'last':now}
            _asn_counts[asn] = rec
        if now - rec['last'] > _TTL:
            rec['c'] = 0
        rec['last'] = now
        rec['c'] += 1
    _total += 1
    try: _asn_distinct_gauge.set(len(_asn_counts))  # type: ignore
    except Exception: pass

def rarity(asn: str | None) -> float:
    if not asn:
        return 0.0
    now = time.time()
    with _lock:
        _maybe_decay(now)
        rec = _asn_counts.get(asn)
        if not rec or now - rec['last'] > _TTL:
            return 0.0
        denom = max(1,_total)
        freq = rec['c']/denom
        return max(0.0, 1.0 - freq * 50)  # amplify rarity; cap at ~1 for very low frequency


def percentile(asn: str | None) -> float:
    """Return percentile rank of ASN frequency (0..1), lower means rarer."""
    if not asn:
        return 1.0
    with _lock:
        counts = [rec['c'] for rec in _asn_counts.values()]
        if not counts:
            return 1.0
        counts_sorted = sorted(counts)
        rec = _asn_counts.get(asn)
        if not rec:
            # treat unseen as rare (0.0)
            return 0.0
        val = rec['c']
        # percentile rank
        less = sum(1 for c in counts_sorted if c < val)
        return less / len(counts_sorted)


def populate_from_source(sample: dict | None = None):
    """Best-effort helper to seed ASN counts from an external sample dict mapping asn->count.
    If sample is None, no-op. Tests and CI can call this to seed values."""
    global _total
    if not sample:
        return
    with _lock:
        for a, c in (sample or {}).items():
            rec = _asn_counts.get(a)
            if not rec:
                rec = {'c': 0, 'last': time.time()}
                _asn_counts[a] = rec
            rec['c'] = float(c)
            rec['last'] = time.time()
            _total += float(c)
    try: _asn_distinct_gauge.set(len(_asn_counts))
    except Exception: pass

def get_current_asn_distinct() -> int:
    now = time.time()
    with _lock:
        _maybe_decay(now)
        return len(_asn_counts)

