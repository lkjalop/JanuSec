from __future__ import annotations

import os
from typing import Dict

# Global registry of factor -> observed flag
_FLAGS: Dict[str, bool] = {}

def set_observed(name: str, observed: bool) -> None:
    if not isinstance(name, str) or not name:
        return
    _FLAGS[name] = bool(observed)

def is_observed(name: str) -> bool:
    try:
        return bool(_FLAGS.get(name, False))
    except Exception:
        return False

def adjust_delta(name: str, inc: float) -> float:
    """Return 0.0 if factor is in observe-mode, else original increment."""
    try:
        return 0.0 if is_observed(name) else float(inc or 0.0)
    except Exception:
        return float(inc or 0.0)

__all__ = ['set_observed','is_observed','adjust_delta']
