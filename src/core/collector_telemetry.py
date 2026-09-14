from __future__ import annotations
from typing import Dict, Any, Optional
from datetime import datetime
from src.core.log_schema import CollectorProvenance
import json
import os

TELEMETRY_DIR = os.environ.get("COLLECTOR_TELEMETRY_DIR", "data/collector_telemetry")


def _ensure_dir():
    os.makedirs(TELEMETRY_DIR, exist_ok=True)


def ingest_collector_telemetry(collector_id: str, payload: Dict[str, Any]) -> None:
    """Persist a simple JSON record per collector (append)."""
    _ensure_dir()
    ts = datetime.utcnow().isoformat() + "Z"
    record = {"collector_id": collector_id, "ts": ts, "payload": payload}
    path = os.path.join(TELEMETRY_DIR, f"{collector_id}.log")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def read_last_collector_status(collector_id: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(TELEMETRY_DIR, f"{collector_id}.log")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        if not lines:
            return None
        last = json.loads(lines[-1])
        return last
