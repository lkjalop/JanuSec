import json
import os
from typing import Dict, Any


def _path() -> str:
    return os.path.join('data', 'factor_weights_current.json')


def get_current_weights() -> Dict[str, float]:
    p = _path()
    if not os.path.exists(p):
        return {}
    try:
        with open(p, 'r', encoding='utf-8') as fh:
            j = json.load(fh)
            return j.get('weights') or {}
    except Exception:
        return {}


def get_rollout_pct() -> float:
    p = _path()
    if not os.path.exists(p):
        return 0.0
    try:
        with open(p, 'r', encoding='utf-8') as fh:
            j = json.load(fh)
            return float(j.get('rollout_pct') or 0.0)
    except Exception:
        return 0.0
