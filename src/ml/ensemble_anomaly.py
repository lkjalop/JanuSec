"""Ensemble Anomaly Scorer.

Combines lightweight feature engineering + optional IsolationForest to produce
an interpretable anomaly score 0..1.

Features (per point) derived from recent window:
 - delta (x_t - x_{t-1})
 - ewma (simple, alpha=0.3)
 - rolling_mean, rolling_std
 - normalized_value (z-like)

If scikit-learn IsolationForest available and ENABLE_ISO_ENSEMBLE flag set,
train a small forest on window to derive anomaly score. Fallback: robust z-score.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence
import math, os


def _flag(name: str, default: bool = True) -> bool:
    try:
        v = os.getenv(name)
        if v is None:
            return default
        return v.lower() in {'1','true','yes','on'}
    except Exception:
        return default


@dataclass
class WindowState:
    values: List[float] = field(default_factory=list)
    ewma: float = 0.0
    count: int = 0


class EnsembleAnomaly:
    def __init__(self, window: int = 64, alpha: float = 0.3) -> None:
        self.enabled = _flag('ENABLE_ENSEMBLE_ANOMALY', True)
        self.use_iso = _flag('ENABLE_ISO_ENSEMBLE', False)
        self.window = int(window)
        self.alpha = float(alpha)
        self.state = WindowState()
        self._iso = None
        if self.use_iso:
            try:
                from sklearn.ensemble import IsolationForest  # type: ignore
                self._iso = IsolationForest(n_estimators=25, contamination='auto', random_state=17)
            except Exception:
                self._iso = None
                self.use_iso = False

    def reset(self) -> None:
        self.state = WindowState()

    def _update_ewma(self, x: float) -> None:
        st = self.state
        if st.count == 0:
            st.ewma = x
        else:
            st.ewma = self.alpha * x + (1 - self.alpha) * st.ewma
        st.count += 1

    def _features(self, series: Sequence[float]) -> List[List[float]]:
        feats: List[List[float]] = []
        if not series:
            return feats
        rolling_mean = 0.0
        # single-pass computation
        for i, x in enumerate(series):
            rolling_mean += (x - rolling_mean) / (i + 1)
            # rolling std naive
            if i < 2:
                std = 0.0
            else:
                mean_i = sum(series[: i + 1]) / (i + 1)
                var = sum((v - mean_i) ** 2 for v in series[: i + 1]) / (i + 1)
                std = math.sqrt(var + 1e-9)
            prev = series[i - 1] if i > 0 else x
            delta = x - prev
            norm = (x - rolling_mean) / (std + 1e-9)
            feats.append([delta, rolling_mean, std, norm])
        return feats

    def ingest(self, x: float) -> dict:
        if not self.enabled:
            return {'value': float(x), 'score': 0.0, 'method': 'disabled'}
        st = self.state
        st.values.append(float(x))
        if len(st.values) > self.window:
            st.values = st.values[-self.window:]
        self._update_ewma(float(x))
        series = st.values
        feats = self._features(series)
        feat_vector = feats[-1] if feats else [0.0, 0.0, 0.0, 0.0]
        # IsolationForest path
        iso_score = None
        if self.use_iso and self._iso and len(feats) >= 10:
            try:
                import numpy as np  # type: ignore

                arr = np.array(feats)
                self._iso.fit(arr)
                decision = float(self._iso.decision_function(arr[-1:].reshape(1, -1))[0])
                # Invert and scale to 0..1
                iso_score = max(0.0, min(1.0, 0.5 - decision))
            except Exception:
                iso_score = None
        # fallback robust z: median absolute deviation
        fallback = 0.0
        if len(series) >= 8:
            sorted_vals = sorted(series)
            mid = len(sorted_vals) // 2
            median_val = sorted_vals[mid]
            mad = sorted(abs(v - median_val) for v in series)[mid] + 1e-9
            fallback = min(1.0, abs(series[-1] - median_val) / (6 * mad))
        score = iso_score if iso_score is not None else fallback
        return {
            'value': float(x),
            'score': float(score),
            'method': 'iso' if iso_score is not None else 'mad',
            'features': feat_vector,
            'ewma': st.ewma,
        }

    def batch_score(self, series: Sequence[float]) -> List[dict]:
        self.reset()
        out: List[dict] = []
        for x in series:
            out.append(self.ingest(float(x)))
        return out


GLOBAL_ENSEMBLE_ANOMALY = EnsembleAnomaly()

__all__ = ['EnsembleAnomaly', 'GLOBAL_ENSEMBLE_ANOMALY']
