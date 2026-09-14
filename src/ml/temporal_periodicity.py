from __future__ import annotations

import os
from typing import Deque, List
from collections import deque


class LombScargleLite:
    """Optional temporal periodicity check using SciPy if available.

    Enabled when ENABLE_LS_TEMPORAL is set; returns False (no anomaly) when disabled/unavailable.
    We maintain a small deque of timestamps and check for strong periodicity; for demo we simply
    return True when jitter is low and period is stable.
    """

    def __init__(self, window: int = 128) -> None:
        self.enabled = os.getenv('ENABLE_LS_TEMPORAL','0').lower() in {'1','true','yes'}
        self._times: Deque[float] = deque(maxlen=max(16, window))
        try:
            if self.enabled:
                import scipy.signal  # type: ignore  # noqa: F401
        except Exception:
            self.enabled = False

    def add(self, ts: float) -> None:
        self._times.append(float(ts))

    def periodic_severity(self) -> float:
        """Return 0..1 severity of periodicity anomaly; 0=no anomaly, 1=strong periodic beacon."""
        if not self.enabled:
            return 0.0
        try:
            if len(self._times) < 16:
                return 0.0
            times = list(self._times)
            deltas = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 > t1]
            if len(deltas) < 8:
                return 0.0
            mean = sum(deltas) / len(deltas)
            var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
            # Score: lower variance relative to mean -> higher severity
            rel = 0.0
            if mean > 0:
                rel = max(0.0, min(1.0, (mean / (var + 1e-9)) / 10.0))
            return float(rel)
        except Exception:
            return 0.0

    def periodic_anomaly(self) -> float:
        """Compatibility shim: tests expect a `periodic_anomaly()` method.

        Returns a float in 0..1 where higher means more periodic (more anomalous).
        This simply forwards to `periodic_severity()` for now.
        """
        try:
            return float(self.periodic_severity())
        except Exception:
            return 0.0


GLOBAL_TEMPORAL = LombScargleLite()

