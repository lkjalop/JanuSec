"""Central shared incidents store with lightweight file persistence.

Optional env vars:
  INCIDENT_STORE_PATH  — JSONL file path (default: data/incidents.jsonl)
  INCIDENT_STORE_MAX   — max entries kept in memory (default: 1000)

On import the store is loaded from disk when the file exists.
Every append is flushed to disk so incidents survive restarts.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List

_LOCK = threading.Lock()


def _store_path() -> str:
    return os.getenv('INCIDENT_STORE_PATH', os.path.join('data', 'incidents.jsonl'))


def _max_entries() -> int:
    try:
        return int(os.getenv('INCIDENT_STORE_MAX', '1000'))
    except Exception:
        return 1000


def _load_from_disk() -> List[Dict[str, Any]]:
    path = _store_path()
    if not os.path.exists(path):
        return []
    entries: List[Dict[str, Any]] = []
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return entries[-_max_entries():]  # keep only most recent


def _append_to_disk(entry: Dict[str, Any]) -> None:
    path = _store_path()
    try:
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        with open(path, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(entry, default=str) + '\n')
    except Exception:
        pass


class _PersistentStore(list):  # type: ignore[type-arg]
    """A list subclass whose append() also writes through to disk."""

    def append(self, item: Dict[str, Any]) -> None:  # type: ignore[override]
        with _LOCK:
            super().append(item)
            # trim in-memory cap
            cap = _max_entries()
            if len(self) > cap:
                del self[:len(self) - cap]
        _append_to_disk(item)

    def clear(self) -> None:  # type: ignore[override]
        with _LOCK:
            super().clear()
        try:
            path = _store_path()
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


INCIDENT_STORE: List[Dict[str, Any]] = _PersistentStore(_load_from_disk())

