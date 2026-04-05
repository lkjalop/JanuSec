"""EWMA baselines for per-entity feature tracking.

This is a lightweight in-memory implementation suitable for demo and unit tests.
Production would back this with Redis or a persistent store.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class EWMAState:
    mean: float = 0.0
    var: float = 0.0
    alpha: float = 0.3
    initialized: bool = False
    last_ts: float = field(default_factory=time.time)

    def update(self, value: float, ts: float | None = None):
        if ts is None:
            ts = time.time()
        if not self.initialized:
            self.mean = value
            self.var = 0.0
            self.initialized = True
            self.last_ts = ts
            return
        self.last_ts = ts
        delta = value - self.mean
        self.mean = self.mean + self.alpha * delta
        # exponential moving variance (approx)
        self.var = (1 - self.alpha) * (self.var + self.alpha * delta * delta)

    def zscore(self, value: float) -> float:
        sd = math.sqrt(self.var) if self.var > 0 else 0.0
        if sd == 0:
            return 0.0 if abs(value - self.mean) < 1e-9 else float('inf')
        return (value - self.mean) / sd


class EWMARegistry:
    """Registry of per-entity EWMA states for multiple named features."""

    def __init__(self, alpha: float = 0.3):
        self.alpha = alpha
        self._store: dict[str, dict[str, EWMAState]] = {}

    def update(self, entity: str, feature: str, value: float, ts: float | None = None):
        ent = self._store.setdefault(entity, {})
        st = ent.get(feature)
        if st is None:
            st = EWMAState(alpha=self.alpha)
            ent[feature] = st
        st.update(value, ts)

    def zscore(self, entity: str, feature: str, value: float) -> float:
        ent = self._store.get(entity)
        if not ent:
            return float('inf')
        st = ent.get(feature)
        if not st:
            return float('inf')
        return st.zscore(value)

    def get_state(self, entity: str, feature: str) -> EWMAState | None:
        return self._store.get(entity, {}).get(feature)
