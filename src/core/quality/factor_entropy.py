"""Factor entropy / usefulness tracking.

Approximate factor informational value: track occurrence counts and compute
entropy contribution to gauge discriminative power.
"""
from __future__ import annotations
from collections import defaultdict
from math import log2
from typing import Dict

try:
    from prometheus_client import Gauge
except Exception:
    Gauge = lambda *a, **k: None  # type: ignore

_factor_entropy = Gauge('factor_entropy_estimate','Approx entropy contribution per factor', ['factor']) if callable(Gauge) else None
_factor_count = defaultdict(int)
_total = 0

def observe_factors(factors):
    global _total
    for f in factors:
        _factor_count[f] += 1
        _total += 1
    if _total % 100 == 0:  # periodic update
        for f,c in list(_factor_count.items())[:500]:  # cap export size
            p = c / _total if _total else 0
            if p>0 and _factor_entropy:
                # Self-information approximation: -p*log2(p) (bounded)
                _factor_entropy.labels(factor=f).set(-p*log2(p))

__all__ = ['observe_factors']
