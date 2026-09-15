from __future__ import annotations

"""Lightweight Isolation Forest wrapper with safe fallback.

If scikit-learn is available, use it. Otherwise, fallback to a robust z-score
approximation so callers always get a score in [0,1].
"""

from typing import Iterable, List, Optional


class _FallbackIF:
    def __init__(self):
        self._vals: List[float] = []

    def fit(self, X: Iterable[Iterable[float]]):  # no-op
        # store last feature for simple robust scale; caller should pass 1-D
        try:
            self._vals = [float(v[0]) for v in X if len(v) > 0]
        except Exception:
            self._vals = []
        return self

    def score_samples(self, X: Iterable[Iterable[float]]):
        # MAD-based z-score mapped to [0,1]
        import math
        vals = self._vals
        if not vals:
            for _ in X:
                yield 0.5
            return
        med = sorted(vals)[len(vals)//2]
        mad = sorted([abs(v - med) for v in vals])[len(vals)//2] or 1.0
        for v in X:
            try:
                x = float(v[0])
            except Exception:
                x = 0.0
            z = abs(x - med) / mad
            # squash
            yield 1.0 - (1.0 / (1.0 + math.exp(-z + 2)))


try:  # pragma: no cover - optional dependency
    from sklearn.ensemble import IsolationForest as _SkIF  # type: ignore
except Exception:  # pragma: no cover
    _SkIF = None  # type: ignore


class IsolationForestDetector:
    def __init__(self, n_estimators: int = 50, max_samples: str | int = 'auto', random_state: Optional[int] = None):
        if _SkIF is not None:
            self._impl = _SkIF(n_estimators=n_estimators, max_samples=max_samples, contamination='auto', random_state=random_state)
        else:
            self._impl = _FallbackIF()

    def fit(self, X: Iterable[Iterable[float]]):
        self._impl.fit(X)
        return self

    def score(self, x: Iterable[float]) -> float:
        try:
            # scikit-learn returns (higher -> less anomalous), we map to [0,1] anomalous
            s = list(self._impl.score_samples([list(x)]))[0]
        except Exception:
            return 0.5
        # normalize conservatively if sklearn present; fallback already in [0,1]
        if _SkIF is not None:
            # empirical logistic squash
            import math
            return 1.0 / (1.0 + math.exp(3.0 * s))
        return float(s)

