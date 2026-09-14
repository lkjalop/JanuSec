"""Beacon Analyzer (MVP)

Maintains lightweight per (dst_ip, port) timing to flag low-jitter periodic beacons.
Heuristic:
  - Track last N (<=8) inter-arrival deltas.
  - If we have >=4 deltas and (stdev/mean) < 0.15 and mean interval between 30s and 600s -> emit factors.
"""
from __future__ import annotations

import math
import threading
import time
from collections import defaultdict, deque
from typing import Dict, List, Tuple


class BeaconAnalyzer:
    def __init__(self, max_hist: int = 8):
        self._lock = threading.Lock()
        self._last_ts: dict[tuple[str,int], float] = {}
        self._deltas: dict[tuple[str,int], deque[float]] = defaultdict(lambda: deque(maxlen=max_hist))

    def observe(self, dst_ip: str, port: int, ts: float | None = None) -> list[str]:
        now = ts or time.time()
        key = (dst_ip, port)
        out: list[str] = []
        with self._lock:
            prev = self._last_ts.get(key)
            if prev:
                delta = now - prev
                if 1.0 <= delta <= 3600:  # ignore extreme or instantaneous noise
                    self._deltas[key].append(delta)
            self._last_ts[key] = now
            deltas = list(self._deltas[key])
        if len(deltas) >= 4:
            mean = sum(deltas)/len(deltas)
            var = sum((d-mean)**2 for d in deltas)/len(deltas)
            std = math.sqrt(var)
            if mean >= 30 and mean <= 600 and std/mean < 0.15:
                out.append('beacon_low_jitter')
                if mean > 120:
                    out.append('beacon_periodic')
        return out

_beacon_singleton: BeaconAnalyzer | None = None

def get_beacon_analyzer() -> BeaconAnalyzer:
    global _beacon_singleton
    if _beacon_singleton is None:
        _beacon_singleton = BeaconAnalyzer()
    return _beacon_singleton
