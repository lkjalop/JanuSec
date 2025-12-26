"""DNS NXDOMAIN aggregation per host for Zeek dns.log events.

Events (from dns.log adapter) should include:
  host: origin host (client)
  dns_rcode: numeric or string rcode (e.g., NXDOMAIN)

Maintains rolling counts with TTL for NXDOMAIN rate heuristic.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, Tuple

_TTL = int(__import__('os').getenv('DNS_NX_TTL_SECONDS','900'))
_lock = threading.Lock()
_counts: dict[str, dict] = {}

def record(host: str | None, rcode: str | int | None):
    if not host:
        return
    now = time.time()
    with _lock:
        rec = _counts.get(host)
        if not rec:
            rec = {'nxd':0,'total':0,'last':now}
            _counts[host] = rec
        # prune stale host counts lazily
        if now - rec['last'] > _TTL:
            rec['nxd'] = 0; rec['total'] = 0
        rec['last'] = now
        rec['total'] += 1
        if isinstance(rcode, str) and 'NXDOMAIN' in rcode.upper():
            rec['nxd'] += 1
        elif rcode == 3:  # typical NXDOMAIN numeric
            rec['nxd'] += 1

def get(host: str | None) -> tuple[int,int]:
    if not host:
        return (0,0)
    now = time.time()
    with _lock:
        rec = _counts.get(host)
        if not rec:
            return (0,0)
        if now - rec['last'] > _TTL:
            return (0,0)
        return (rec['nxd'], rec['total'])
