"""Adaptive EWMA detector: per-tenant baseline, adaptive alpha, and thresholding.

Simple implementation designed for test/demo: keeps per-tenant state in-memory,
adapts alpha based on recent volatility, and exposes update() API.
"""
from __future__ import annotations
import time
from typing import Dict, Any


class TenantState:
    def __init__(self, value: float = 0.0):
        self.ewma = float(value)
        self.var_ewma = 0.0
        self.alpha = 0.3
        self.count = 0


class AdaptiveEWMA:
    def __init__(self, base_alpha: float = 0.3, min_alpha: float = 0.05, max_alpha: float = 0.9, k: float = 1.0):
        self.base_alpha = float(base_alpha)
        self.min_alpha = float(min_alpha)
        self.max_alpha = float(max_alpha)
        self.k = float(k)
        self.tenants: Dict[str, TenantState] = {}

    def _ensure(self, tenant: str) -> TenantState:
        if tenant not in self.tenants:
            self.tenants[tenant] = TenantState()
        return self.tenants[tenant]

    def update(self, tenant: str, value: float, timestamp: float | None = None, replay: bool = False) -> Dict[str, Any]:
        ts = timestamp or time.time()
        s = self._ensure(tenant)
        # Cold start: initialize on first observation
        if s.count == 0:
            s.ewma = float(value)
            s.var_ewma = 0.0
            s.alpha = self.base_alpha
            s.count = 1
            return {'ewma': s.ewma, 'alpha': s.alpha, 'threshold': 0.0, 'score': 0.0, 'alert': False}

        # Compute delta and update variance EWMA
        delta = float(value) - s.ewma
        # Volatility estimate: EWMA of squared delta
        beta = 1 - s.alpha if s.alpha < 1 else 0.7
        s.var_ewma = beta * s.var_ewma + (1 - beta) * (delta * delta)

        # Adapt alpha based on normalized volatility (higher vol -> higher alpha to react faster)
        vol = (s.var_ewma ** 0.5) if s.var_ewma >= 0 else 0.0
        # Compute z-like normalized measure; avoid division by zero
        denom = vol + 1e-6
        adapt_factor = 1.0 + self.k * (abs(delta) / denom)
        new_alpha = max(self.min_alpha, min(self.max_alpha, self.base_alpha * adapt_factor))
        s.alpha = float(new_alpha)

        # Update EWMA
        s.ewma = (1 - s.alpha) * s.ewma + s.alpha * float(value)

        # Alert score: normalized distance from EWMA
        score = abs(float(value) - s.ewma) / (vol + 1e-6)
        # threshold: simple multiple of vol (e.g., 3*sigma)
        threshold = 3.0 * vol
        alert = score > 3.0 and vol > 1e-9

        s.count += 1

        return {'ewma': s.ewma, 'alpha': s.alpha, 'threshold': threshold, 'score': score, 'alert': alert}
