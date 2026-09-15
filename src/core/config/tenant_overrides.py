"""Per-tenant override configuration loader.

Supports runtime overrides for thresholds & quality floors:
  - block_threshold
  - escalate_threshold
  - min_block_quality
  - min_escalate_quality
  - promotion_min_sessions (reserved for future use)
  - promotion_min_emergence (reserved)

Storage precedence:
  1. JSON file path from env TENANT_OVERRIDES_PATH (default artifacts/config/tenant_overrides.json)
  2. If missing file, returns empty mapping and creates directory lazily on write.

Endpoints in server read & write updates (admin-only for modifications).
File format example:
{
  "acme": {"block_threshold": 0.92, "escalate_threshold": 0.7},
  "default": {"block_threshold": 0.9}
}
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict

_CACHE: dict[str, Any] = {}
_CACHE_MTIME: float | None = None
_LOCK = threading.Lock()

def _path() -> str:
    return os.getenv('TENANT_OVERRIDES_PATH','artifacts/config/tenant_overrides.json')

def _load() -> dict[str, Any]:
    global _CACHE, _CACHE_MTIME
    path = _path()
    try:
        st = os.stat(path)
        mtime = st.st_mtime
    except FileNotFoundError:
        _CACHE = {}
        _CACHE_MTIME = None
        return _CACHE
    if _CACHE_MTIME is not None and mtime == _CACHE_MTIME:
        return _CACHE
    try:
        with open(path,encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict):
                _CACHE = data
            else:
                _CACHE = {}
    except Exception:
        _CACHE = {}
    _CACHE_MTIME = mtime
    return _CACHE

def list_overrides() -> dict[str, Any]:
    with _LOCK:
        return _load().copy()

def get_overrides(tenant: str) -> dict[str, Any]:
    with _LOCK:
        data = _load()
        return data.get(tenant) or data.get('default') or {}

def upsert_overrides(tenant: str, overrides: dict[str, Any]):
    path = _path()
    with _LOCK:
        data = _load()
        if tenant in data:
            data[tenant].update(overrides)
        else:
            data[tenant] = overrides
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp,'w',encoding='utf-8') as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
        # Force cache invalidate
        global _CACHE_MTIME
        _CACHE_MTIME = None
