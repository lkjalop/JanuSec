"""Centralized temporary file tracking and orphan cleanup for worker blobs.

Workers (and helpers) should register created temp files here so the
application can attempt lifecycle cleanup on shutdown or startup (sweep).
"""
from __future__ import annotations

import os
import time
import threading
from typing import Set

_TRACKED: Set[str] = set()
_LOCK = threading.Lock()


def register_temp(path: str) -> None:
    try:
        with _LOCK:
            _TRACKED.add(path)
    except Exception:
        pass


def unregister_temp(path: str) -> None:
    try:
        with _LOCK:
            _TRACKED.discard(path)
    except Exception:
        pass


def sweep_orphans(prefix: str = 'threat_pcap_', suffix: str = '.pcap', older_than_seconds: int = 3600) -> int:
    """Remove files in the temp directory that look like our artifacts.

    Returns number of files removed.
    """
    removed = 0
    now = time.time()
    tmpdir = os.getenv('TMP', None) or os.getenv('TEMP', None) or '/tmp'
    try:
        for name in os.listdir(tmpdir):
            if not name.startswith(prefix) or not name.endswith(suffix):
                continue
            path = os.path.join(tmpdir, name)
            try:
                mtime = os.path.getmtime(path)
                if now - mtime > older_than_seconds:
                    os.remove(path)
                    removed += 1
                    unregister_temp(path)
            except Exception:
                continue
    except Exception:
        pass
    return removed


def list_tracked() -> Set[str]:
    with _LOCK:
        return set(_TRACKED)
