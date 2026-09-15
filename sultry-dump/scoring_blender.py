"""Scoring blender: combine heuristic (synthesize) and optional ML prediction with adaptive alpha.
ML model is pluggable (callable) returning score 0..1 and confidence 0..1.
"""
from __future__ import annotations
from typing import Callable, Tuple
import math

# Default adaptive params
BASE_ALPHA = 0.6
MIN_ALPHA = 0.3
MAX_ALPHA = 0.85
VOL_SCALE = 0.4


def adaptive_alpha(heuristic_scores: list[float]) -> float:
    # volatility = stddev(mean-normalized non-zero scores)
    vals = [v for v in heuristic_scores if v is not None]
    if not vals:
        return BASE_ALPHA
    mean = sum(vals)/len(vals)
    var = sum((v-mean)**2 for v in vals)/len(vals)
    vol = math.sqrt(var)
    alpha = BASE_ALPHA - (vol * VOL_SCALE)
    return max(MIN_ALPHA, min(MAX_ALPHA, alpha))


def blend(heuristic_score: float, ml_predictor: Callable[[dict], Tuple[float,float]] | None = None, obs: dict | None = None, adaptive: bool = True) -> dict:
    # ml_predictor returns (score, confidence)
    if ml_predictor is None:
        return {'score': heuristic_score, 'alpha': 1.0, 'ml_score': None, 'ml_conf': None}
    try:
        ml_score, ml_conf = ml_predictor(obs or {})
        alpha = BASE_ALPHA
        if adaptive:
            # derive alpha from heuristic dispersion if available
            # heuristic_scores placeholder: use heuristic_score only -> low volatility
            alpha = adaptive_alpha([heuristic_score])
        # prefer ml when confidence high
        blended = alpha * heuristic_score + (1.0 - alpha) * ml_score
        return {'score': blended, 'alpha': alpha, 'ml_score': ml_score, 'ml_conf': ml_conf}
    except Exception:
        return {'score': heuristic_score, 'alpha': 1.0, 'ml_score': None, 'ml_conf': None}
