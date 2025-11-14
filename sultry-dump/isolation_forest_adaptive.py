"""Lightweight adaptive isolation forest wrapper.

This is a small helper that wraps sklearn's IsolationForest when available,
and provides a simple fallback scoring heuristic when sklearn is not installed.
"""
from typing import Sequence, List

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False


def fit_iforest(features: Sequence[Sequence[float]], random_state: int = 0, n_estimators: int = 100):
    """Fit an IsolationForest if sklearn available, else return None."""
    if not SKLEARN_AVAILABLE:
        return None
    model = IsolationForest(n_estimators=n_estimators, random_state=random_state)
    model.fit(features)
    return model


def score_samples(model, features: Sequence[Sequence[float]]) -> List[float]:
    """Return anomaly scores between 0..1 (1 = anomaly). If no model, use simple fallback.
    """
    if model is None:
        # fallback: compute z-score-like heuristic per feature vector magnitude
        out = []
        mags = [sum(f) for f in features]
        if not mags:
            return []
        mean = sum(mags) / len(mags)
        var = sum((m - mean) ** 2 for m in mags) / len(mags)
        std = var ** 0.5 if var > 0 else 1.0
        for m in mags:
            z = abs((m - mean) / std)
            out.append(min(1.0, z / 3.0))
        return out
    # sklearn IsolationForest: decision_function negative for anomalies -> map to 0..1
    raw = model.decision_function(features)
    # normalize to 0..1 (higher = more anomalous)
    mn, mx = min(raw), max(raw)
    if mx - mn == 0:
        return [0.0 for _ in raw]
    return [1.0 - ((r - mn) / (mx - mn)) for r in raw]
