"""Time-of-Day profile scaffolding (Stage 4).

Provides a minimal service to track 24 hourly EWMA counts per entity and
compute a divergence/z-score for a given event hour against the entity profile.

This is intentionally small and synchronous-friendly; persistence and async
wrappers can be added later.
"""
from __future__ import annotations

import math
import time
from typing import Dict, List, Tuple


_DEFAULT_ALPHA = 0.2


class TimeOfDayProfile:
    """Stores a 24-bin EWMA for an entity."""

    def __init__(self, alpha: float | None = None):
        self.alpha = float(alpha or _DEFAULT_ALPHA)
        self.bins: List[float] = [0.0] * 24
        self.counts_total: float = 0.0
        self.last_ts: float = 0.0

    def update(self, hour: int, value: float = 1.0, ts: float | None = None) -> None:
        h = int(hour) % 24
        v = float(value)
        # EWMA update for the bin
        self.bins[h] = self.bins[h] + self.alpha * (v - self.bins[h])
        self.counts_total += v
        self.last_ts = float(ts or time.time())

    def get_mean(self) -> float:
        return sum(self.bins) / 24.0

    def get_std(self) -> float:
        mean = self.get_mean()
        var = sum((b - mean) ** 2 for b in self.bins) / max(1, 24 - 1)
        return math.sqrt(var)

    def z_for_hour(self, hour: int) -> float:
        h = int(hour) % 24
        mean = self.get_mean()
        std = max(1e-6, self.get_std())
        return (self.bins[h] - mean) / std


class TimeOfDayService:
    """Simple in-memory service to hold profiles per entity key."""

    def __init__(self):
        self._profiles: Dict[str, TimeOfDayProfile] = {}

    def update(self, entity_key: str, hour: int, value: float = 1.0, ts: float | None = None) -> None:
        p = self._profiles.get(entity_key)
        if p is None:
            p = TimeOfDayProfile()
            self._profiles[entity_key] = p
        p.update(hour, value, ts=ts)

    def get_profile(self, entity_key: str) -> TimeOfDayProfile | None:
        return self._profiles.get(entity_key)

    def divergence(self, entity_key: str, hour: int, value: float = 1.0) -> dict:
        """Return a small dictionary with z and raw deviation for the hour."""
        p = self.get_profile(entity_key)
        if p is None:
            return {'z': 0.0, 'mean': 0.0, 'stddev': 0.0, 'samples': 0}
        z = p.z_for_hour(hour)
        return {'z': z, 'mean': p.get_mean(), 'stddev': p.get_std(), 'samples': int(p.counts_total)}


TOD = TimeOfDayService()

__all__ = ['TOD', 'TimeOfDayService', 'TimeOfDayProfile']
