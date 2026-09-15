"""Simple Isolation Forest wrapper. Optional scikit-learn dependency; if missing, functions will raise on import.
"""
from __future__ import annotations
from typing import Optional, List

try:
    from sklearn.ensemble import IsolationForest  # type: ignore
except Exception:
    IsolationForest = None  # type: ignore

try:
    import numpy as _np  # type: ignore
except Exception:
    _np = None  # type: ignore


class IFWrapper:
    def __init__(self, n_estimators: int = 100, contamination: float = 0.01):
        self._fallback = IsolationForest is None
        if self._fallback:
            self.model = None
            self._mean = None
            self._std = None
            return
        self.model = IsolationForest(n_estimators=n_estimators, contamination=contamination)
        self.fitted = False

    def fit(self, X):
        if self._fallback:
            if _np is None:
                raise RuntimeError('numpy not available')
            arr = _np.asarray(X, dtype=float)
            self._mean = arr.mean(axis=0)
            self._std = arr.std(axis=0)
            self._std[self._std == 0] = 1.0
            self.fitted = True
            return
        self.model.fit(X)
        self.fitted = True

    def score(self, X):
        if not self.fitted:
            raise RuntimeError('model not fitted')
        if self._fallback:
            arr = _np.asarray(X, dtype=float)
            z = (arr - self._mean) / self._std
            return _np.sqrt((z ** 2).sum(axis=1))
        # IsolationForest.decision_function: higher is normal; invert to make anomaly score
        return -self.model.decision_function(X)
