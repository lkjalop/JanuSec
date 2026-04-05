"""Composite triage score utilities.

Normalizes inputs to [0,1] and computes a weighted composite triage_score.
Weights are configurable via env `TRIAGE_WEIGHTS_JSON` or defaults below.
"""
from __future__ import annotations

import json
import os
from typing import Dict, Any

DEFAULT_WEIGHTS = {
    'dread': 0.35,
    'correlation': 0.25,
    'density': 0.15,
    'confidence': 0.15,
    'rarity': 0.10
}


def _load_weights() -> Dict[str, float]:
    try:
        raw = os.getenv('TRIAGE_WEIGHTS_JSON')
        if raw:
            w = json.loads(raw)
            if isinstance(w, dict):
                # copy provided weights (allow subset) and merge defaults for missing keys
                out = {k: float(v) for k, v in w.items() if isinstance(v, (int, float))}
                for dk, dv in DEFAULT_WEIGHTS.items():
                    if dk not in out:
                        out[dk] = dv
                # normalize final dict to sum to 1
                total = sum(out.values())
                if total <= 0:
                    return DEFAULT_WEIGHTS
                return {k: float(v) / total for k, v in out.items()}
    except Exception:
        pass
    return DEFAULT_WEIGHTS


def _normalize(val: Any, minv: float = 0.0, maxv: float = 1.0) -> float:
    try:
        v = float(val)
    except Exception:
        return 0.0
    if maxv <= minv:
        return 0.0
    if v <= minv:
        return 0.0
    if v >= maxv:
        return 1.0
    # linear normalization
    return (v - minv) / (maxv - minv)


def compute_triage_score(inputs: Dict[str, Any], weights: Dict[str, float] | None = None) -> Dict[str, Any]:
    """Compute composite triage score from inputs.

    inputs expected keys (optional): dread, correlation, density, confidence, rarity
    Each is numeric or None. Returns dict with triage_score and breakdown.
    """
    w = _load_weights() if weights is None else weights
    # ensure we have weights for all keys in DEFAULT_WEIGHTS
    for k in DEFAULT_WEIGHTS:
        if k not in w:
            w[k] = DEFAULT_WEIGHTS[k]
    # Normalize each input: assume dread in 0-10 scale, correlation 0..1, density 0..1, confidence 0..1, rarity 0..1
    dread_norm = _normalize(inputs.get('dread') or 0.0, 0.0, 10.0)
    corr_norm = _normalize(inputs.get('correlation') or 0.0, 0.0, 1.0)
    dens_norm = _normalize(inputs.get('density') or 0.0, 0.0, 1.0)
    conf_norm = _normalize(inputs.get('confidence') or inputs.get('risk_confidence') or 0.0, 0.0, 1.0)
    rarity_norm = _normalize(inputs.get('rarity') or 0.0, 0.0, 1.0)

    breakdown = {
        'dread': dread_norm,
        'correlation': corr_norm,
        'density': dens_norm,
        'confidence': conf_norm,
        'rarity': rarity_norm,
    }
    # weighted sum
    score = (
        breakdown['dread'] * w.get('dread', 0.0)
        + breakdown['correlation'] * w.get('correlation', 0.0)
        + breakdown['density'] * w.get('density', 0.0)
        + breakdown['confidence'] * w.get('confidence', 0.0)
        + breakdown['rarity'] * w.get('rarity', 0.0)
    )
    triage_score = max(0.0, min(1.0, score))
    return {'triage_score': round(triage_score, 4), 'breakdown': breakdown, 'weights': w}
