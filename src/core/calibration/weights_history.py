from __future__ import annotations
import time, threading
from typing import Dict, List, Tuple

_HISTORY: Dict[str, List[Tuple[float, float]]] = {}
_LOCK = threading.RLock()
_MAX_POINTS = 64

def record_weight(factor: str, weight: float) -> None:
    with _LOCK:
        arr = _HISTORY.setdefault(factor, [])
        arr.append((time.time(), float(weight)))
        if len(arr) > _MAX_POINTS:
            # keep most recent
            _HISTORY[factor] = arr[-_MAX_POINTS:]

def get_history(factor: str) -> List[Tuple[float, float]]:
    with _LOCK:
        return list(_HISTORY.get(factor, []))

__all__ = ['record_weight','get_history']
