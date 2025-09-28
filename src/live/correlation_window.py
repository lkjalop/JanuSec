"""Correlation window buffer for short-term multi-event heuristics.

Maintains per-key (host, user, dest_ip) recent events with timestamps
in memory. Used for sequence-based rule expansions (future beacons, burst rates).
"""
from __future__ import annotations
import time
from collections import deque, defaultdict
from typing import Deque, Dict, Any, Tuple, List
import os, threading

_MAX_EVENTS = int(os.getenv('CORR_WINDOW_MAX_EVENTS','5000'))
_TTL_SECONDS = int(os.getenv('CORR_WINDOW_TTL_SECONDS','900'))  # 15m
_lock = threading.Lock()
_by_host: Dict[str, Deque[Tuple[float,dict]]] = defaultdict(lambda: deque())
_by_user: Dict[str, Deque[Tuple[float,dict]]] = defaultdict(lambda: deque())
_by_dest: Dict[str, Deque[Tuple[float,dict]]] = defaultdict(lambda: deque())
_total = 0

def _prune(q: Deque[Tuple[float,dict]], now: float):
    while q and (now - q[0][0]) > _TTL_SECONDS:
        q.popleft()

def add(ev: dict):
    global _total
    now = ev.get('ts') or time.time()
    host = ev.get('host'); user = ev.get('user'); dest = ev.get('dest_ip')
    with _lock:
        if host:
            hq = _by_host[host]; hq.append((now, ev)); _prune(hq, now)
        if user:
            uq = _by_user[user]; uq.append((now, ev)); _prune(uq, now)
        if dest:
            dq = _by_dest[dest]; dq.append((now, ev)); _prune(dq, now)
        _total += 1
        # Global size bounding (rough)
        if _total > _MAX_EVENTS:
            # Drop oldest from largest deque category (simplistic)
            for coll in (_by_host, _by_user, _by_dest):
                for k, dq in list(coll.items()):
                    if dq and _total > int(_MAX_EVENTS*0.9):
                        dq.popleft(); _total -= 1
                    if not dq:
                        coll.pop(k, None)

def recent_for_host(host: str, limit: int = 50) -> List[dict]:
    with _lock:
        q = _by_host.get(host)
        if not q: return []
        return [ev for _,ev in list(q)[-limit:]]

def snapshot_stats():
    with _lock:
        return {
            'ttl_seconds': _TTL_SECONDS,
            'hosts_tracked': len(_by_host),
            'users_tracked': len(_by_user),
            'dest_tracked': len(_by_dest),
            'approx_total': _total
        }
