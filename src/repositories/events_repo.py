"""Events Repository"""
from __future__ import annotations
import json
from typing import Any, Dict, Optional
from db.database import execute, fetchrow, with_retry

INSERT_EVENT = """
INSERT INTO events (id, source, event_type, severity, ts_original, raw_payload)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (id) DO UPDATE SET
    source = EXCLUDED.source,
    event_type = EXCLUDED.event_type,
    severity = EXCLUDED.severity,
    ts_original = EXCLUDED.ts_original,
    raw_payload = EXCLUDED.raw_payload
"""

GET_EVENT = "SELECT * FROM events WHERE id=$1"

async def upsert_event(event: Dict[str, Any]):
    async def _do():
        return await execute(
            INSERT_EVENT,
            event.get('id'),
            event.get('source'),
            event.get('event_type'),
            event.get('severity'),
            event.get('timestamp'),
            json.dumps(event.get('details', {}))
        )
    return await with_retry(_do)

async def get_event(event_id: str) -> Optional[Dict[str, Any]]:
    row = await fetchrow(GET_EVENT, event_id)
    return dict(row) if row else None
