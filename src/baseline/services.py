"""Baseline services for NXDOMAIN rate and ASN rarity.

Lightweight in-memory tracking; production should persist or window by time.
"""
from __future__ import annotations

import os
import time
import threading
from collections import defaultdict, deque
from typing import Dict, Any

_DNS_EVENTS: deque[tuple[float, bool]] = deque(maxlen=10000)  # (ts, success)
_ASN_COUNTS: Dict[str, int] = defaultdict(int)
_LOCK = threading.Lock()
_ASN_TIMES: Dict[str, float] = defaultdict(float)


ASN_TTL = int(os.getenv('ASN_RARITY_TTL_SECONDS', '86400'))

def record_dns_event(success: bool) -> None:
    with _LOCK:
        _DNS_EVENTS.append((time.time(), success))

def record_asn(asn: str) -> None:
    if not asn:
        return
    with _LOCK:
        _ASN_COUNTS[str(asn)] += 1
        _ASN_TIMES[str(asn)] = time.time()

def get_nxdomain_baseline(window_seconds: int = 3600) -> Dict[str, Any]:
    now = time.time()
    with _LOCK:
        events = [e for e in _DNS_EVENTS if (now - e[0]) <= window_seconds]
    total = len(events)
    fails = len([1 for _, ok in events if not ok])
    rate = (fails / total) if total else 0.0
    # Dynamic threshold: mean rate + 0.15 or floor 0.35 whichever higher (demo heuristic)
    threshold = max(0.35, rate + 0.15)
    return {'window_seconds': window_seconds, 'total_queries': total, 'nxdomain': fails, 'rate': round(rate,4), 'threshold': round(threshold,4)}

def get_asn_rarity() -> Dict[str, Any]:
    with _LOCK:
        # prune old ASNs
        now = time.time()
        for a, t in list(_ASN_TIMES.items()):
            if now - t > ASN_TTL:
                _ASN_COUNTS.pop(a, None)
                _ASN_TIMES.pop(a, None)
        counts = dict(_ASN_COUNTS)
    total = sum(counts.values()) or 1
    rarity = {}
    # Rarity score: inverse frequency normalized 0..1
    max_inv = 0.0
    inv_map = {}
    for asn, c in counts.items():
        inv = 1.0 / c
        inv_map[asn] = inv
        if inv > max_inv:
            max_inv = inv
    if max_inv <= 0:
        max_inv = 1.0
    for asn, inv in inv_map.items():
        # apply light smoothing
        score = inv / max_inv
        rarity[asn] = round(min(1.0, max(0.0, score)), 4)
    return {'total_events': total, 'asn_counts': counts, 'rarity_scores': rarity}
