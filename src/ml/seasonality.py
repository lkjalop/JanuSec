"""Moving-Window Seasonality Decomposition.

Lightweight STL-inspired approach (without external deps) for short series:
 - Maintain recent values in a ring buffer
 - Estimate period via autocorrelation peak (optional) or provided period
 - Compute seasonal component as average per position modulo period
 - Residual = value - seasonal_component

Outputs a seasonality-normalized residual anomaly score (z-like) and provides
helpers to batch compute decomposition for a given series.

Environment Overrides:
 - SEASONAL_MAX_WINDOW: cap window length (default 360)
 - SEASONAL_MIN_PERIOD, SEASONAL_MAX_PERIOD: search bounds for auto period
 - ENABLE_SEASONALITY: flag to enable (default on)

We intentionally keep numeric stability with small eps values and clamp scores
to -10..10 for safety. Anomaly severity is normalized 0..1 using logistic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence
import math, os


def _flag(name: str, default: bool = True) -> bool:
    try:
        v = os.getenv(name)
        if v is None:
            return default
        return v.lower() in {'1','true','yes','on'}
    except Exception:
        return default


def _int_env(name: str, default: int) -> int:
    try:
        v = int(os.getenv(name, str(default)) or default)
        return v
    except Exception:
        return default


@dataclass
class SeasonalState:
    values: List[float] = field(default_factory=list)
    period: int = 0
    seasonal: List[float] = field(default_factory=list)  # per position avg


class SeasonalityDecomposer:
    def __init__(self, max_window: int | None = None, auto: bool = True) -> None:
        self.enabled = _flag('ENABLE_SEASONALITY', True)
        self.max_window = max_window or _int_env('SEASONAL_MAX_WINDOW', 360)
        self.min_period = _int_env('SEASONAL_MIN_PERIOD', 4)
        self.max_period = _int_env('SEASONAL_MAX_PERIOD', 60)
        self.auto = auto
        self.state = SeasonalState()

    def reset(self) -> None:
        self.state = SeasonalState()

    def _auto_period(self, series: Sequence[float]) -> int:
        # naive autocorrelation-based period search
        best_p, best_score = 0, -1.0
        n = len(series)
        for p in range(self.min_period, min(self.max_period, n // 2) + 1):
            score = 0.0
            cnt = 0
            for i in range(n - p):
                score += series[i] * series[i + p]
                cnt += 1
            if cnt > 0:
                score /= cnt
            if score > best_score:
                best_score, best_p = score, p
        return best_p if best_p > 0 else 0

    def _recompute_seasonal(self) -> None:
        st = self.state
        if st.period <= 1:
            st.seasonal = []
            return
        buckets = [[0.0, 0] for _ in range(st.period)]
        for idx, v in enumerate(st.values):
            b = idx % st.period
            buckets[b][0] += v
            buckets[b][1] += 1
        st.seasonal = [ (s / c) if c > 0 else 0.0 for s, c in buckets ]

    def ingest(self, x: float) -> dict:
        """Ingest a value and return decomposition for this point.

        Returns { 'value': x, 'seasonal': s, 'residual': r, 'resid_score': anomaly }.
        """
        if not self.enabled:
            return {'value': float(x), 'seasonal': 0.0, 'residual': 0.0, 'resid_score': 0.0}
        st = self.state
        st.values.append(float(x))
        # maintain window cap
        if len(st.values) > self.max_window:
            st.values = st.values[-self.max_window:]
        # discover period if needed when we have enough points
        if self.auto and (st.period == 0) and len(st.values) >= self.min_period * 3:
            st.period = self._auto_period(st.values)
            if st.period > 1:
                self._recompute_seasonal()
        # update seasonal averages if period known
        if st.period > 1:
            self._recompute_seasonal()
            pos = (len(st.values) - 1) % st.period
            seasonal_val = st.seasonal[pos] if pos < len(st.seasonal) else 0.0
        else:
            seasonal_val = 0.0
        resid = float(x) - seasonal_val
        # approximate residual anomaly via rolling mean/std of recent residuals
        resid_hist = st.values[-max(st.period * 2, 12):] if st.period > 0 else st.values[-12:]
        mean_val = sum(resid_hist) / len(resid_hist)
        var = sum((v - mean_val) ** 2 for v in resid_hist) / len(resid_hist)
        std = math.sqrt(var + 1e-9)
        z = (float(x) - mean_val) / (std + 1e-9)
        z = max(-10.0, min(10.0, z))
        # logistic to 0..1 anomaly severity (higher absolute z increases severity)
        severity = 1.0 / (1.0 + math.exp(-abs(z))) - 0.5  # center small deviations near 0
        return {'value': float(x), 'seasonal': seasonal_val, 'residual': resid, 'resid_score': severity}

    def batch_decompose(self, series: Sequence[float]) -> List[dict]:
        self.reset()
        out: List[dict] = []
        for x in series:
            out.append(self.ingest(float(x)))
        return out


GLOBAL_SEASONALITY = SeasonalityDecomposer()

__all__ = ['SeasonalityDecomposer', 'GLOBAL_SEASONALITY']
