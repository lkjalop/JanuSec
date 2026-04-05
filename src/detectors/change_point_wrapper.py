"""Lightweight change-point detection wrapper using ruptures (optional)."""
from __future__ import annotations
from typing import Optional, List

try:
    import ruptures as rpt  # type: ignore
except Exception:
    rpt = None


class CPDWrapper:
    def __init__(self, model: str = 'rbf'):
        if rpt is None:
            raise RuntimeError('ruptures not available')
        self.model = model

    def detect(self, series, pen: float = 10.0) -> List[int]:
        algo = rpt.Pelt(model=self.model).fit(series)
        return algo.predict(pen=pen)
