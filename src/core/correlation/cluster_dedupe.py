"""Simple clustering/deduplication heuristic.

Groups events by sorted factor signature (excluding timings) and emits cluster markers.
This reduces analyst fatigue by marking duplicates.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Dict, List, Tuple

# In-memory signature cache (rolling)
_seen: dict[str,int] = defaultdict(int)

EXCLUDE_PREFIXES = ('timings:',)

def cluster_mark(factors: list[str]) -> list[str]:
    core = [f for f in factors if not f.startswith(EXCLUDE_PREFIXES)]
    if not core:
        return []
    sig_basis = '|'.join(sorted(core)[:40])
    sig_hash = hashlib.sha1(sig_basis.encode()).hexdigest()[:16]
    count = _seen[sig_hash]
    _seen[sig_hash] += 1
    if count == 0:
        return [f'cluster_first:{sig_hash}']
    elif count < 5:
        return [f'cluster_duplicate:{sig_hash}']
    else:
        # Frequent pattern, can be flagged as noise if desired later
        return [f'cluster_repeated:{sig_hash}']

def reset_cluster_cache() -> None:
    _seen.clear()

__all__ = ['cluster_mark', 'reset_cluster_cache']
