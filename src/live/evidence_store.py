
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


def append(record: Dict[str, Any]) -> None:
    data = json.dumps(record, separators=(',', ':'))
    encoded = (data + '\n').encode('utf-8')
    with _LOCK:
        _ensure_dir(_EVIDENCE_PATH)
        if _EVIDENCE_PATH.exists() and _EVIDENCE_PATH.stat().st_size + len(encoded) > _MAX_BYTES:
            _rotate(_EVIDENCE_PATH)
        with _EVIDENCE_PATH.open('ab') as fh:
            fh.write(encoded)


__all__ = ['append']

