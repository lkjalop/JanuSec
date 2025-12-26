"""Domain reputation baseline tracking (eTLD+1 frequency & suspicious TLD heuristic) with decay.

Decay model similar to ASN: every DOMAIN_DECAY_INTERVAL_SECONDS multiply counts by DOMAIN_DECAY_FACTOR.
Env vars:
    DOMAIN_DECAY_INTERVAL_SECONDS (default 0 -> disabled)
    DOMAIN_DECAY_FACTOR (default 0.9)
Metrics:
    domain_distinct_current
    domain_decay_runs_total
"""
from __future__ import annotations

import os
import re
import threading
import time
from typing import Dict, Tuple
from functools import lru_cache

_TTL = int(__import__('os').getenv('DOMAIN_BASELINE_TTL_SECONDS','86400'))
_lock = threading.Lock()
_freq: dict[str, dict] = {}
_total = 0
_DECAY_INTERVAL = int(os.getenv('DOMAIN_DECAY_INTERVAL_SECONDS','0'))
_DECAY_FACTOR = float(os.getenv('DOMAIN_DECAY_FACTOR','0.9'))
_LAST_DECAY = time.time()

try:  # pragma: no cover
    from prometheus_client import Counter as _C, Gauge as _G  # type: ignore
    _domain_distinct_gauge = _G('domain_distinct_current','Current distinct eTLD+1 domains tracked')  # type: ignore
    _domain_decay_runs = _C('domain_decay_runs_total','Domain baseline decay runs')  # type: ignore
    _baseline_hits = _C('baseline_cache_hits_total','Baseline cache hits')  # type: ignore
    _baseline_misses = _C('baseline_cache_misses_total','Baseline cache misses')  # type: ignore
except Exception:  # pragma: no cover
    class _Stub:
        def set(self,*a,**k): return None
        def inc(self,*a,**k): return None
    _domain_distinct_gauge = _Stub(); _domain_decay_runs = _Stub(); _baseline_hits=_Stub(); _baseline_misses=_Stub()

def _maybe_decay(now: float):
    global _LAST_DECAY
    if _DECAY_INTERVAL <= 0:
        return
    if now - _LAST_DECAY < _DECAY_INTERVAL:
        return
    for d, rec in list(_freq.items()):
        rec['c'] *= _DECAY_FACTOR
        if rec['c'] < 0.5:
            _freq.pop(d, None)
    _LAST_DECAY = now
    try: _domain_decay_runs.inc()  # type: ignore
    except Exception: pass
    try: _domain_distinct_gauge.set(len(_freq))  # type: ignore
    except Exception: pass
_SUSPICIOUS_TLDS = {t.strip().lower() for t in (__import__('os').getenv('SUSPICIOUS_TLDS','xyz,top,click,cfd,zip').split(',')) if t}
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

def _etl_plus_one(domain: str) -> str:
    parts = domain.lower().split('.')
    if len(parts) < 2:
        return domain.lower()
    return '.'.join(parts[-2:])  # naive eTLD+1

def record(domain: str | None):
    global _total
    if not domain or not _DOMAIN_RE.match(domain):
        return
    now = time.time()
    key = _etl_plus_one(domain)
    with _lock:
        _maybe_decay(now)
        rec = _freq.get(key)
        if not rec:
            rec = {'c':0,'last':now,'tld':key.split('.')[-1]}
            _freq[key] = rec
        if now - rec['last'] > _TTL:
            rec['c'] = 0
        rec['last'] = now
        rec['c'] += 1
    _total += 1
    # invalidate single key entry if present (per-key granularity maintains locality)
    try: _CACHE.pop(key, None)
    except Exception: pass
    try: _domain_distinct_gauge.set(len(_freq))  # type: ignore
    except Exception: pass

_CACHE: dict[str, tuple[int,float,bool,int,int]] = {}
_CACHE_MAX = 512

def _cache_get(key: str, snapshot_total: int, minute_slice: int) -> tuple[int,float,bool]:
    entry = _CACHE.get(key)
    if entry and entry[3] == snapshot_total and entry[4] == minute_slice:
        try: _baseline_hits.inc()  # type: ignore
        except Exception: pass
        return (entry[0], entry[1], entry[2])
    base = _freq.get(key)
    if not base:
        try: _baseline_misses.inc()  # type: ignore
        except Exception: pass
        return (0,0.0,False)
    freq = base['c']/max(1,snapshot_total)
    suspicious_tld = base['tld'] in _SUSPICIOUS_TLDS
    if len(_CACHE) >= _CACHE_MAX and key not in _CACHE:
        # simple eviction: pop arbitrary first item
        try: _CACHE.pop(next(iter(_CACHE)))
        except Exception: pass
    _CACHE[key] = (base['c'], freq, suspicious_tld, snapshot_total, minute_slice)
    try: _baseline_misses.inc()  # type: ignore
    except Exception: pass
    return (base['c'], freq, suspicious_tld)

def stats(domain: str | None) -> tuple[int,float,bool]:
    if not domain:
        return (0,0.0,False)
    key = _etl_plus_one(domain)
    now = time.time()
    with _lock:
        _maybe_decay(now)
        rec = _freq.get(key)
        if not rec or now - rec['last'] > _TTL:
            return (0,0.0,False)
        minute = int(now//60)
    return _cache_get(key, _total, minute)

def get_current_domain_distinct() -> int:
    """Return current distinct domain count (after potential decay)."""
    now = time.time()
    with _lock:
        _maybe_decay(now)
        return len(_freq)

