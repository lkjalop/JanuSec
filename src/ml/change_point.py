"""Lightweight Change-Point Detection Utilities.

Provides:
 - Streaming CUSUM detector (no external deps)
 - Optional PELT wrapper (uses `ruptures` if installed and enabled via env)

Design Goals:
 - Fail-safe: returns empty detections if disabled or errors occur
 - Low overhead: O(n) memory for batch, small constant state for streaming
 - Interpretability: each detection returns direction (up/down) + raw score

Environment Flags:
 - ENABLE_CHANGE_POINT in {'1','true','yes'} enables detectors (default on)
 - ENABLE_PELT in {'1','true','yes'} attempts to import `ruptures` for PELT

Detection Result Schema (dict):
 {
   'index': int,            # index in provided series
   'ts': float | None,      # optional timestamp if provided
   'method': 'cusum'|'pelt',
   'score': float,          # raw detection score
   'direction': 'up'|'down' # direction of change
 }
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence
import math, os


def _env_flag(name: str, default: bool = True) -> bool:
    try:
        val = os.getenv(name)
        if val is None:
            return default
        return val.lower() in {'1','true','yes','on'}
    except Exception:
        return default


@dataclass
class CUSUMState:
    pos: float = 0.0
    neg: float = 0.0
    mean: float = 0.0
    count: int = 0


class ChangePointDetector:
    """Streaming CUSUM change-point detector with batch helpers."""

    def __init__(self, threshold: float = 5.0, drift: float = 0.0, adapt: bool = True) -> None:
        self.enabled = _env_flag('ENABLE_CHANGE_POINT', True)
        self.state = CUSUMState()
        self.threshold = float(threshold)
        self.drift = float(drift)
        self.adapt = bool(adapt)

    def reset(self) -> None:
        self.state = CUSUMState()

    def _update_mean(self, x: float) -> None:
        # Welford-like incremental mean (simple form)
        st = self.state
        st.count += 1
        st.mean += (x - st.mean) / st.count

    def ingest(self, x: float) -> Optional[dict]:
        """Ingest a single value; return detection dict if threshold crossed else None."""
        if not self.enabled:
            return None
        st = self.state
        prev_mean = st.mean
        self._update_mean(x)
        mean = st.mean
        # deviation relative to (adaptive) mean
        dev = x - mean if self.adapt else x - prev_mean
        # update positive/negative cumulative sums
        st.pos = max(0.0, st.pos + dev - self.drift)
        st.neg = max(0.0, st.neg - dev - self.drift)
        det = None
        if st.pos > self.threshold:
            det = {'index': st.count - 1, 'ts': None, 'method': 'cusum', 'score': st.pos, 'direction': 'up'}
            st.pos = 0.0  # reset after detection
        elif st.neg > self.threshold:
            det = {'index': st.count - 1, 'ts': None, 'method': 'cusum', 'score': st.neg, 'direction': 'down'}
            st.neg = 0.0
        return det

    # --------------- Batch API ---------------
    def batch_detect_cusum(self, series: Sequence[float], timestamps: Optional[Sequence[float]] = None) -> List[dict]:
        if not self.enabled:
            return []
        self.reset()
        detections: List[dict] = []
        for i, x in enumerate(series):
            d = self.ingest(float(x))
            if d:
                if timestamps is not None and i < len(timestamps):
                    d['ts'] = float(timestamps[i])
                detections.append(d)
        return detections

    def batch_detect_pelt(self, series: Sequence[float], penalty: float = 3.0) -> List[dict]:
        """Attempt PELT via optional `ruptures` lib. Returns empty list if unavailable/disabled."""
        if not self.enabled or not _env_flag('ENABLE_PELT', False):
            return []
        try:
            import numpy as np  # type: ignore
            import ruptures as rpt  # type: ignore
        except Exception:
            return []
        try:
            arr = np.array(series).astype(float)
            algo = rpt.Pelt(model='rbf').fit(arr)
            bkps = algo.predict(pen=penalty)
            # bkps includes final point; exclude terminal breakpoint
            results: List[dict] = []
            for idx in bkps[:-1]:
                direction = 'up'
                if 1 < idx < len(arr):
                    # crude direction heuristic: compare local means
                    m1 = arr[max(0, idx-5):idx].mean() if idx > 0 else arr[:idx].mean()
                    m2 = arr[idx: min(len(arr), idx+5)].mean() if idx < len(arr) else arr[idx:].mean()
                    if m2 < m1:
                        direction = 'down'
                results.append({'index': int(idx-1), 'ts': None, 'method': 'pelt', 'score': float(idx), 'direction': direction})
            return results
        except Exception:
            return []


# Global instance for convenience (streaming usage)
GLOBAL_CHANGE_POINT = ChangePointDetector()

__all__ = ['ChangePointDetector', 'GLOBAL_CHANGE_POINT']
