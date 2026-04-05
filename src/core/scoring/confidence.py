"""Shared confidence scoring helpers."""
from __future__ import annotations

from typing import Iterable


def normalize_score(s: float) -> float:
    """Clamp and normalize a raw score into [0.0, 1.0]."""
    try:
        v = float(s)
    except Exception:
        return 0.0
    if v != v:  # NaN
        return 0.0
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def combine_scores(scores: Iterable[float], method: str = 'max') -> float:
    """Combine multiple normalized scores into an overall confidence.

    Supported methods: 'max' (default), 'mean', 'prod' (1 - product of (1-s)).
    """
    arr = [normalize_score(s) for s in (scores or [])]
    if not arr:
        return 0.0
    if method == 'mean':
        return sum(arr) / len(arr)
    if method == 'prod':
        prod = 1.0
        for a in arr:
            prod *= (1.0 - a)
        return 1.0 - prod
    # default to max
    return max(arr)
