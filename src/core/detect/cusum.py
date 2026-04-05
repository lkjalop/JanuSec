from __future__ import annotations

"""Tiny CUSUM detector for mean shift on streaming features.

Use: keep one instance per (entity, feature), update(value) returns True when shift detected.
Defaults are conservative; tune thresholds via constructor if needed.
"""

from dataclasses import dataclass


@dataclass
class CUSUM:
    target_mean: float = 0.0
    k: float = 0.5  # slack
    h: float = 5.0  # threshold

    def __post_init__(self):
        self._gp = 0.0
        self._gn = 0.0

    def update(self, x: float) -> bool:
        # One-sided CUSUM (detect increase); mirrored for decrease
        s = x - self.target_mean - self.k
        self._gp = max(0.0, self._gp + s)
        self._gn = min(0.0, self._gn + s)  # track negative too
        if self._gp > self.h:
            self._gp = 0.0
            return True
        if abs(self._gn) > self.h:
            self._gn = 0.0
            return True
        return False

