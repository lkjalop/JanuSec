"""Repository for replay delta summaries."""
from __future__ import annotations
from typing import Any, Dict, List
from db.database import fetch, with_retry
import json, uuid

INSERT = """
INSERT INTO replay_deltas (event_id, original_verdict, new_verdict, original_confidence, new_confidence, confidence_delta, since_window, sample_run_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
RETURNING id
"""

RECENT = """
SELECT id, created_at, event_id, original_verdict, new_verdict, original_confidence, new_confidence, confidence_delta, since_window, sample_run_id
FROM replay_deltas
ORDER BY created_at DESC
LIMIT $1
"""

async def insert_delta(delta: Dict[str, Any], since_window: str, sample_run_id: str):
    async def _do():
        return await fetch(INSERT, delta['event_id'], delta['original_verdict'], delta['new_verdict'], delta['original_confidence'], delta['new_confidence'], delta['confidence_delta'], since_window, sample_run_id)
    row = await with_retry(_do)
    return dict(row) if row else None

async def list_recent(limit: int = 100) -> List[Dict[str, Any]]:
    rows = await fetch(RECENT, limit)
    return [dict(r) for r in rows]

__all__ = ['insert_delta','list_recent']
