"""Playbook DB loader with optional TTL caching and admin reload.

This module provides:
 - `get_playbook_for_mitre(mitre_id)` -> dict
 - `list_mitre_ids()` -> list[str]
 - `reload()` -> None (force re-read from disk)

Caching:
 - Controlled by env `PLAYBOOK_DB_TTL_SECONDS` (int). If unset or <=0, caching is unlimited
   until `reload()` is called.
 - Thread-safe via a module-level lock.
"""
from __future__ import annotations
import json
import os
import threading
import time
from typing import Any, Dict, Optional, List

_DB_PATH = os.path.join(os.getcwd(), 'data', 'playbooks', 'mitre_playbooks.json')
_CACHE: Optional[Dict[str, Any]] = None
_CACHE_TS: float = 0.0
_LOCK = threading.RLock()

# TTL config (seconds). If <= 0, cache does not expire automatically.
try:
    _TTL_SECONDS = int(os.getenv('PLAYBOOK_DB_TTL_SECONDS') or 0)
except Exception:
    _TTL_SECONDS = 0


def _read_from_disk() -> Dict[str, Any]:
    try:
        if os.path.exists(_DB_PATH):
            with open(_DB_PATH, 'r', encoding='utf-8') as fh:
                return json.load(fh) or {}
    except Exception:
        pass
    return {}


def _load_db() -> Dict[str, Any]:
    """Return cached DB if valid otherwise read from disk and populate cache."""
    global _CACHE, _CACHE_TS
    now = time.time()
    with _LOCK:
        if _CACHE is not None:
            if _TTL_SECONDS and _TTL_SECONDS > 0:
                if (now - _CACHE_TS) < float(_TTL_SECONDS):
                    return _CACHE
            else:
                return _CACHE
        # cache miss or expired
        db = _read_from_disk()
        _CACHE = db
        _CACHE_TS = now
        return _CACHE


def get_playbook_for_mitre(mitre_id: str) -> Dict[str, Any]:
    if not mitre_id:
        return {}
    mitre_key = str(mitre_id).upper()
    db = _load_db()
    try:
        return db.get(mitre_key) or {}
    except Exception:
        return {}


def list_mitre_ids() -> List[str]:
    db = _load_db()
    try:
        return sorted(list(db.keys()))
    except Exception:
        return []


def reload() -> None:
    """Force reload the DB from disk and reset cache timestamp.

    Intended to be called by an admin API endpoint during runtime.
    """
    global _CACHE, _CACHE_TS
    with _LOCK:
        _CACHE = _read_from_disk()
        _CACHE_TS = time.time()


__all__ = ["get_playbook_for_mitre", "list_mitre_ids", "reload"]
