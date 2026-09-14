
"""Lightweight evidence store for JSONL append with rotation."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from threading import Lock
from typing import Any, Dict

_EVIDENCE_PATH = Path(os.getenv('EVIDENCE_FILE_PATH', 'data/evidence/evidence.jsonl'))
_MAX_BYTES = int(os.getenv('EVIDENCE_MAX_BYTES', str(5 * 1024 * 1024)))  # 5 MB default
_ROTATION_SUFFIX = os.getenv('EVIDENCE_ROTATION_SUFFIX', 'rotated')
_LOCK = Lock()


def _ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _rotate(path: Path) -> None:
    timestamp = time.strftime('%Y%m%d-%H%M%S')
    base = f"{path.stem}.{_ROTATION_SUFFIX}-{timestamp}"
    rotated = path.with_name(f'{base}{path.suffix}')
    counter = 1
    while rotated.exists():
        rotated = path.with_name(f'{base}-{counter}{path.suffix}')
        counter += 1
    path.rename(rotated)


def append(record: dict[str, Any]) -> None:
    # Refresh env-derived settings on each append to be robust in test harnesses
    # which may set environment variables after initial import.
    try:
        path = Path(os.getenv('EVIDENCE_FILE_PATH', str(_EVIDENCE_PATH)))
        max_bytes = int(os.getenv('EVIDENCE_MAX_BYTES', str(_MAX_BYTES)))
        rotation_suffix = os.getenv('EVIDENCE_ROTATION_SUFFIX', _ROTATION_SUFFIX)
    except Exception:
        # Fallback to module-level defaults if env parsing fails
        path = _EVIDENCE_PATH
        max_bytes = _MAX_BYTES
        rotation_suffix = _ROTATION_SUFFIX
    data = json.dumps(record, separators=(',', ':'))
    encoded = (data + '\n').encode('utf-8')
    with _LOCK:
        # Ensure directory for the target path
        _ensure_dir(path)
        if path.exists() and path.stat().st_size + len(encoded) > max_bytes:
            # Use the runtime-obtained rotation suffix when renaming
            # Temporarily override module-level rotation suffix for _rotate
            old = globals().get('_ROTATION_SUFFIX')
            globals()['_ROTATION_SUFFIX'] = rotation_suffix
            try:
                _rotate(path)
            finally:
                if old is not None:
                    globals()['_ROTATION_SUFFIX'] = old
        with path.open('ab') as fh:
            fh.write(encoded)


__all__ = ['append']

