"""Runtime rule thresholds backed by env defaults and optional on-disk persistence.

This module provides a tiny in-memory store for thresholds used by high-signal
rules so they can be tuned at runtime via an admin API. Values default from
environment variables but can be updated and persisted to a JSON file.
"""
from __future__ import annotations

import json
import os
from threading import RLock
from typing import Any, Dict

_lock = RLock()
_path = os.getenv('RULE_THRESHOLDS_PATH', 'data/rule_thresholds.json')

# sensible defaults (also configurable via env)
_defaults: Dict[str, Any] = {
    'lateral_conn_count': int(os.getenv('LATERAL_CONN_COUNT', '30')),
    'rapid_scan_rate': float(os.getenv('RAPID_SCAN_RATE', '100.0')),
    'exfil_bytes': int(os.getenv('EXFIL_BYTES', str(5_000_000))),
    # Account/auth thresholds (used by T1078 correlation rules)
    'auth_success_count': int(os.getenv('AUTH_SUCCESS_COUNT', '5')),
    'account_new_mass': bool(os.getenv('ACCOUNT_NEW_MASS', 'False')),
    'src_unusual': bool(os.getenv('SRC_UNUSUAL_DEFAULT', 'False')),
}

# runtime store
_store: Dict[str, Any] = {}


def _ensure_loaded() -> None:
    global _store
    with _lock:
        if _store:
            return
        # start from defaults
        _store = dict(_defaults)
        # overlay persisted values when present
        try:
            if os.path.exists(_path):
                with open(_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    _store.update(data)
        except Exception:
            # best-effort: ignore persistence errors
            pass


def get_threshold(name: str) -> Any:
    _ensure_loaded()
    return _store.get(name, _defaults.get(name))


def set_threshold(name: str, value: Any, persist: bool = True) -> None:
    _ensure_loaded()
    with _lock:
        _store[name] = value
        if persist:
            try:
                os.makedirs(os.path.dirname(_path) or '.', exist_ok=True)
                with open(_path, 'w', encoding='utf-8') as f:
                    json.dump(_store, f)
            except Exception:
                # ignore persistence errors; runtime change still applies
                pass


def to_dict() -> Dict[str, Any]:
    _ensure_loaded()
    return dict(_store)


def reset_to_env_defaults(persist: bool = True) -> None:
    global _store
    with _lock:
        _store = dict(_defaults)
        if persist:
            try:
                os.makedirs(os.path.dirname(_path) or '.', exist_ok=True)
                with open(_path, 'w', encoding='utf-8') as f:
                    json.dump(_store, f)
            except Exception:
                pass
