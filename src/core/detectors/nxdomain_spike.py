"""NXDOMAIN spike detector reads runtime DNS trackers and computes recent NX rate.

Returns factor objects suitable for inclusion in HopGraph `factors` list.
"""
from typing import Any, Dict, List

def detect_nxdomain_spike(runtime: Any, threshold: float = 0.35, min_samples: int = 5) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    if runtime is None:
        return results
    try:
        nx = getattr(runtime, 'nx_rate_tracker', None) or {}
        for producer, dq in nx.items():
            try:
                vals = list(dq)
            except Exception:
                continue
            if not vals or len(vals) < min_samples:
                continue
            # compute rate as fraction of truthy entries
            rate = 0.0
            try:
                rate = sum(1 for v in vals if v) / max(1, len(vals))
            except Exception:
                continue
            if rate >= threshold:
                results.append({'factor':'nxdomain_rate_high','producer':str(producer),'nx_rate':round(rate,3),'score':round(min(1.0, rate),3),'reason':f'nxdomain rate {rate:.2f} observed for {producer}'})
    except Exception:
        pass
    return results
