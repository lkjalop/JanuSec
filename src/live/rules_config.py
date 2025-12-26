"""Rule weight externalization for FAST_LIVE_MODE.
Supports YAML (PyYAML) or JSON; returns empty weights if file missing.
"""
from __future__ import annotations

import json
import os
from typing import Dict

try:
    import yaml  # type: ignore
except Exception:
    yaml = None  # type: ignore

_PATH = os.getenv('RULES_CONFIG_PATH','config/fast_rules.yaml')
_cached: dict[str,float] = {}
_mtime = 0.0

def _parse(blob: str) -> dict[str,float]:
    if _PATH.endswith('.json') or yaml is None:
        data = json.loads(blob)
    else:
        data = yaml.safe_load(blob)  # type: ignore
    if not isinstance(data, dict):
        return {}
    rules = data.get('rules')
    if not isinstance(rules, dict):
        return {}
    out: dict[str,float] = {}
    for k,v in rules.items():
        if isinstance(v, dict):
            w = v.get('weight')
        else:
            w = v
        try:
            out[str(k)] = float(w)
        except Exception:
            continue
    return out

def _maybe_reload():
    global _mtime, _cached
    if not os.path.exists(_PATH):
        return
    st = os.stat(_PATH)
    if st.st_mtime <= _mtime:
        return
    try:
        with open(_PATH,encoding='utf-8') as f:
            blob = f.read()
        weights = _parse(blob)
        _cached = weights
        _mtime = st.st_mtime
    except Exception:
        pass

def get_weights() -> dict[str,float]:
    _maybe_reload()
    return dict(_cached)
