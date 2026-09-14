from __future__ import annotations
from typing import Dict, List, Optional
import itertools
import random


def grid_over_factors(factors: List[str], base: float = 0.0, step: float = 0.5, levels: int = 3, max_candidates: Optional[int] = 50, seed: Optional[int] = None) -> List[Dict[str, float]]:
    """Generate candidate weight dicts over provided factor names.

    - `levels` controls the number of discrete weight values per factor.
    - `max_candidates` optionally limits the number of returned candidates by sampling.
    - `seed` makes sampling deterministic for tests.
    """
    if not factors:
        return []
    ranges = [ [base + i*step for i in range(levels)] for _ in factors ]
    all_combos = list(itertools.product(*ranges))
    if seed is not None:
        random.seed(seed)
    if max_candidates and len(all_combos) > max_candidates:
        sampled = random.sample(all_combos, max_candidates)
    else:
        sampled = all_combos
    candidates = [ {f: float(w) for f, w in zip(factors, combo)} for combo in sampled ]
    return candidates


__all__ = ['grid_over_factors']
