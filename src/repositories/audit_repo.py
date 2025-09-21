"""Audit Log Repository"""
from __future__ import annotations
import json
from typing import Any, Dict, Optional
from db.database import execute, fetchrow, fetch, with_retry

INSERT_AUDIT = """
INSERT INTO audit_log (event_id, action, details, custody_hash, prev_hash)
VALUES ($1,$2,$3::jsonb,$4,$5)
RETURNING id, custody_hash
"""

GET_LAST_AUDIT = """
SELECT custody_hash FROM audit_log WHERE event_id=$1 ORDER BY id DESC LIMIT 1
"""
GET_CHAIN = """
SELECT id, action, custody_hash, prev_hash, created_at, details
FROM audit_log WHERE event_id=$1 ORDER BY id ASC
"""

async def append_audit(event_id: str, action: str, details: Dict[str, Any], custody_hash: str, prev_hash: str | None):
    async def _do():
        return await fetchrow(INSERT_AUDIT, event_id, action, json.dumps(details), custody_hash, prev_hash)
    row = await with_retry(_do)
    return dict(row) if row else None

async def get_last_hash(event_id: str) -> Optional[str]:
    row = await fetchrow(GET_LAST_AUDIT, event_id)
    return row['custody_hash'] if row else None

async def get_chain(event_id: str):
    rows = await fetch(GET_CHAIN, event_id)
    return [dict(r) for r in rows]
