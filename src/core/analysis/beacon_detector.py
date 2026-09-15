"""Simple beacon detector using autocorrelation / periodicity on a time series.

This lightweight detector expects a sequence of timestamps (seconds) and
computes a periodicity score in 0..1. It's intentionally approximate and
uses EWMA-smoothed counts when available.
"""
from __future__ import annotations

import math
from typing import Sequence, Tuple


def _autocorr_score(ts: Sequence[float]) -> float:
    """Compute a lightweight periodicity score based on autocorrelation peaks.

    Returns 0..1 where higher indicates stronger periodicity.
    """
    if not ts or len(ts) < 4:
        return 0.0
    # convert to inter-arrival times
    iats = [t2 - t1 for t1, t2 in zip(ts[:-1], ts[1:]) if t2 > t1]
    if not iats:
        return 0.0
    # measure variance vs mean: low variance indicates regular spacing
    mean = sum(iats) / len(iats)
    var = sum((x - mean) ** 2 for x in iats) / len(iats)
    # coefficient of variation
    cov = math.sqrt(var) / mean if mean > 0 else float('inf')
    # Score mapping: cov near 0 => score near 1.0, cov large => score near 0
    try:
        score = max(0.0, min(1.0, 1.0 - (cov / (cov + 1.0))))
    except Exception:
        score = 0.0
    # boost if there are many samples
    if len(iats) >= 8:
        score = min(1.0, score + 0.1)
    return float(score)


def periodicity_from_timestamps(ts: Sequence[float]) -> Tuple[float, dict]:
    """Return (score, details) for a list of timestamps.

    details includes mean_iat, sample_count.
    """
    score = _autocorr_score(ts)
    iats = [t2 - t1 for t1, t2 in zip(ts[:-1], ts[1:]) if t2 > t1]
    mean = (sum(iats) / len(iats)) if iats else 0.0
    return score, {'mean_iat': mean, 'sample_count': len(ts)}
