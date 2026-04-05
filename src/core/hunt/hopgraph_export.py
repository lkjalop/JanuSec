from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, List

EXPORT_DIR = Path(os.getenv('HOPGRAPH_EMIT_DIR', 'data/session_emissions'))
EXPORT_DIR.mkdir(parents=True, exist_ok=True)


def enqueue_emissions(event_id: str, signals: List[dict[str, Any]]):
    # Try to enqueue in-memory queue first for high-throughput; fall back to file storage.
    try:
        from .hopgraph_queue import enqueue as q_enqueue
        q_enqueue(event_id, signals)
        return
    except Exception:
        pass
    try:
        fname = EXPORT_DIR / f"{event_id}.json"
        tmp = fname.with_suffix('.tmp')
        with tmp.open('w', encoding='utf-8') as fh:
            json.dump({'event_id': event_id, 'signals': signals}, fh)
        tmp.replace(fname)
    except Exception:
        # best-effort: ignore errors to avoid affecting pipeline
        pass
