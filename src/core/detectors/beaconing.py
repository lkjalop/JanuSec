"""Simple beaconing detector for HopGraph runtime.

Expects runtime to provide per-batch temporal sequences or dns/http counts.
This is intentionally lightweight and synthetic for demo purposes: it looks
for regular periodic callbacks by checking variance/mean of inter-arrival times
for a given (host,domain) pair supplied via runtime trackers.
"""
from typing import Any, Dict, List, Tuple
import math

def detect_beaconing(runtime: Any) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    if runtime is None:
        return results
    try:
        trackers = getattr(runtime, 'beacon_trackers', None) or {}
        for key, dq in trackers.items():
            try:
                vals = list(dq)
            except Exception:
                continue
            if not vals or len(vals) < 6:
                continue
            # compute inter-arrival times
            iats = []
            prev = None
            for t in vals:
                try:
                    ts = float(t)
                except Exception:
                    continue
                if prev is not None:
                    iats.append(ts - prev)
                prev = ts
            if not iats:
                continue
            mean = sum(iats)/len(iats)
            var = sum((x-mean)**2 for x in iats)/len(iats)
            # coefficient of variation
            cov = math.sqrt(var)/mean if mean > 0 else 0.0
            # low cov and reasonable mean indicate periodic beaconing
            if cov < 0.25 and mean > 1.0 and mean < 3600:
                results.append({'factor':'net_beaconing_periodic','period_seconds':round(mean,2),'cov':round(cov,3),'score':0.7,'producer':str(key)})
    except Exception:
        pass
    return results
