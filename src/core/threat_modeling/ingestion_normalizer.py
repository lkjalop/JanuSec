"""Normalize factor aliases at ingestion boundaries.

This module provides convenience wrappers used by correlation entrypoints
and test helpers so that legacy factor names (for example, the legacy
`net:beacon_like`) are automatically mapped to the canonical
`net:beacon_periodic` name before rule evaluation or metric lookups.

Keep this file minimal — it simply re-uses the existing alias map.
"""
from typing import Iterable, List

try:
    from .factor_aliases import normalize_factor
except Exception:
    # defensive fallback: identity function
    def normalize_factor(f: str) -> str:
        return f


def normalize_factors(factors: Iterable[str]) -> List[str]:
    """Return a list where each factor is normalized to its canonical name.

    Preserves order and duplicates.
    """
    return [normalize_factor(f) for f in factors]
