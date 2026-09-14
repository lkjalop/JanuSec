"""Helpers for safe JSON persistence with coarse locks."""
from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Dict

_LOCKS: Dict[str, threading.RLock] = {}
_GLOBAL_LOCK = threading.Lock()


def _lock_for(path: str) -> threading.RLock:
    abs_path = os.path.abspath(path)
    with _GLOBAL_LOCK:
        lock = _LOCKS.get(abs_path)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[abs_path] = lock
        return lock


def atomic_write_json(path: str, data: Any) -> None:
    """Write JSON atomically to `path` (temp file + replace)."""
    if not path:
        return
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp_path = f"{path}.{uuid.uuid4().hex}.tmp"
    lock = _lock_for(path)
    with lock:
        with open(tmp_path, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, ensure_ascii=False)
        os.replace(tmp_path, path)


def load_json(path: str) -> Any:
    """Load JSON from disk, returning None if path missing or invalid."""
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    lock = _lock_for(path)
    with lock:
        try:
            with open(p, 'r', encoding='utf-8') as fh:
                return json.load(fh)
        except Exception:
            return None
