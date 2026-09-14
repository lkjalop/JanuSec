"""Analyst feedback driven weight calibration (logistic-style incremental).

Adjusts factor weights in the risk configuration based on analyst votes.
Votes: +1 (strengthen weight), -1 (weaken). Applies bounded delta with a
simple learning rate. Persists updates to `risk_config.json` via risk_loader.
"""
from __future__ import annotations

from typing import Dict, Any
import os, json, threading
from src.config import risk_loader
from .weights_history import record_weight  # type: ignore

_LOCK = threading.RLock()
LEARNING_RATE = float(os.getenv('CALIBRATION_LEARNING_RATE','0.05') or 0.05)
MAX_WEIGHT = float(os.getenv('CALIBRATION_MAX_WEIGHT','2.0') or 2.0)
MIN_WEIGHT = float(os.getenv('CALIBRATION_MIN_WEIGHT','0.05') or 0.05)

def apply_vote(factor: str, vote: int) -> Dict[str, Any]:
    """Apply a single analyst vote to update factor weight.

    Returns updated config snapshot (weights only).
    """
    if vote not in (-1, 1):
        raise ValueError('vote must be -1 or 1')
    with _LOCK:
        cfg = risk_loader.current_config()
        weights = dict(cfg.get('weights', {}))
        key = factor.strip()
        if key not in weights:
            # Introduce new factor weight at conservative default if unseen
            weights[key] = MIN_WEIGHT
        delta = LEARNING_RATE * vote
        new_val = max(MIN_WEIGHT, min(MAX_WEIGHT, float(weights[key]) + delta))
        weights[key] = round(new_val, 4)
        try:
            record_weight(key, weights[key])
        except Exception:
            pass
        # Persist merged config
        merged = {**cfg, 'weights': weights}
        path = risk_loader.get_config_path()
        tmp = path + '.tmp'
        try:
            with open(tmp,'w',encoding='utf-8') as fh:
                json.dump(merged, fh, indent=2, sort_keys=True)
            os.replace(tmp, path)
        except Exception as e:
            raise RuntimeError(f'persist_failed:{e}')
        risk_loader.reload_config()
        return weights

__all__ = ['apply_vote']