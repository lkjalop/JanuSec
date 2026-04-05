import json
import os
from pathlib import Path
from typing import Any, Dict, List

HIST_PATH = Path(os.getenv('HISTORICAL_CONTEXT_PATH', 'data/historical_host_context.json'))


def load_host_history(host: str, limit: int = 5) -> List[Dict[str, Any]]:
    if not host:
        return []
    if not HIST_PATH.exists():
        return []
    try:
        with HIST_PATH.open('r', encoding='utf-8') as fh:
            data = json.load(fh)
    except Exception:
        return []
    entries = data.get(host.lower())
    if not isinstance(entries, list):
        return []
    return entries[:limit]


def append_host_event(host: str, event: Dict[str, Any]) -> None:
    if not host or not event:
        return
    host_key = host.lower()
    database: Dict[str, List[Dict[str, Any]]] = {}
    if HIST_PATH.exists():
        try:
            with HIST_PATH.open('r', encoding='utf-8') as fh:
                database = json.load(fh)
        except Exception:
            database = {}
    entries = database.setdefault(host_key, [])
    entries.insert(0, event)
    database[host_key] = entries[:20]
    HIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HIST_PATH.open('w', encoding='utf-8') as fh:
        json.dump(database, fh, indent=2)
