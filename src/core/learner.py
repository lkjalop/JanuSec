"""Light-weight learner placeholder to nudge per-factor weights based on persisted decisions.

This is an in-memory placeholder; in future this can be backed by DB and scheduled retraining.
"""
from __future__ import annotations

from typing import Dict

_LEARNED: Dict[str, float] = {}


def nudge_factor_weight(factor: str, delta: float) -> None:
    _LEARNED[factor] = max(0.0, min(1.0, _LEARNED.get(factor, 0.0) + float(delta)))


def get_learned_weights() -> Dict[str, float]:
    return dict(_LEARNED)
