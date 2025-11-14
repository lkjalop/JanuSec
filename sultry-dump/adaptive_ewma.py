"""Adaptive EWMA helper used to compute smoothed overlap matrices and derive alpha when needed."""
from typing import List, Sequence, Tuple
import math


def ewma(values: Sequence[float], alpha: float) -> List[float]:
    """Compute EWMA series for given values and alpha in (0,1]."""
    if not values:
        return []
    out = [values[0]]
    for v in values[1:]:
        out.append(alpha * v + (1 - alpha) * out[-1])
    return out


def adaptive_alpha_from_counts(counts: Sequence[float], base_alpha: float = 0.6, min_alpha: float = 0.3, max_alpha: float = 0.85, vol_scale: float = 0.4) -> float:
    """Derive alpha from volatility (variance/mean) of non-zero pairwise counts.

    Higher volatility lowers alpha (more smoothing).
    """
    nonzero = [c for c in counts if c > 0]
    if not nonzero:
        return base_alpha
    mean = sum(nonzero) / len(nonzero)
    if mean == 0:
        return base_alpha
    var = sum((c - mean) ** 2 for c in nonzero) / len(nonzero)
    vol = math.sqrt(var) / mean
    alpha = base_alpha - vol_scale * vol
    alpha = max(min_alpha, min(max_alpha, alpha))
    return alpha
