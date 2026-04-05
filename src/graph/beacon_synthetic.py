"""Synthetic beacon event generator for testing beacon detection & graph correlation."""
from __future__ import annotations
import time, random
from typing import List, Dict

def generate_beacon_series(host: str, dst: str, base_period: float = 60.0, count: int = 20, jitter: float = 0.1, start_ts: float | None = None) -> List[Dict]:
    start = start_ts or time.time()
    events = []
    for i in range(count):
        ts = start + i * base_period
        # Apply +/- jitter * period
        delta = (random.random()*2 - 1) * jitter * base_period
        events.append({
            'event_id': f'beacon-{host}-{i}',
            'ts': ts + delta,
            'src_host': host,
            'dst_host': dst,
            'dst_ip': dst,
            'dst_port': 443,
            'protocol': 'tcp'
        })
    return events

__all__ = ['generate_beacon_series']
