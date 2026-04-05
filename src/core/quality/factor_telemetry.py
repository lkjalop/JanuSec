"""Shared helpers for persisting and loading factor telemetry snapshots."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict

_DEFAULT_PATH = 'data/factor_synthesis_telemetry.json'
_PATH_ENV = 'FACTOR_SYNTHESIS_TELEMETRY_PATH'


def _telemetry_path() -> Path:
    """Return the configured telemetry persistence path."""
    return Path(os.getenv(_PATH_ENV, _DEFAULT_PATH))


def load_factor_telemetry() -> Dict[str, Any]:
    """Load the most recent telemetry snapshot from disk."""
    path = _telemetry_path()
    if not path.exists():
        return {}
    try:
        with path.open('r', encoding='utf-8') as fh:
            payload = json.load(fh) or {}
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def persist_factor_telemetry(snapshot: Dict[str, Any]) -> None:
    """Persist telemetry snapshot to disk with a fresh timestamp."""
    if not isinstance(snapshot, dict):
        return
    payload = dict(snapshot)
    payload.setdefault('timestamp', time.time())
    path = _telemetry_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True), encoding='utf-8')
    except Exception:
        # Best-effort persistence; ignore filesystem failures
        return


__all__ = ['load_factor_telemetry', 'persist_factor_telemetry']
