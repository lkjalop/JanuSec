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
import time, threading, re, os
from typing import Dict, Tuple

_TTL = int(__import__('os').getenv('DOMAIN_BASELINE_TTL_SECONDS','86400'))
_lock = threading.Lock()
_freq: Dict[str, dict] = {}
_total = 0
_DECAY_INTERVAL = int(os.getenv('DOMAIN_DECAY_INTERVAL_SECONDS','0'))
_DECAY_FACTOR = float(os.getenv('DOMAIN_DECAY_FACTOR','0.9'))
_LAST_DECAY = time.time()

try:  # pragma: no cover
    from prometheus_client import Gauge as _G, Counter as _C  # type: ignore
    _domain_distinct_gauge = _G('domain_distinct_current','Current distinct eTLD+1 domains tracked')  # type: ignore
    _domain_decay_runs = _C('domain_decay_runs_total','Domain baseline decay runs')  # type: ignore
except Exception:  # pragma: no cover
    class _Stub:
        def set(self,*a,**k): return None
        def inc(self,*a,**k): return None
    _domain_distinct_gauge = _Stub(); _domain_decay_runs = _Stub()

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
    try: _domain_distinct_gauge.set(len(_freq))  # type: ignore
    except Exception: pass

def stats(domain: str | None) -> Tuple[int,float,bool]:
    if not domain:
        return (0,0.0,False)
    key = _etl_plus_one(domain)
    now = time.time()
    with _lock:
        _maybe_decay(now)
        rec = _freq.get(key)
        if not rec or now - rec['last'] > _TTL:
            return (0,0.0,False)
        freq = rec['c']/max(1,_total)
        suspicious_tld = rec['tld'] in _SUSPICIOUS_TLDS
        return (rec['c'], freq, suspicious_tld)

def get_current_domain_distinct() -> int:
    """Return current distinct domain count (after potential decay)."""
    now = time.time()
    with _lock:
        _maybe_decay(now)
        return len(_freq)

