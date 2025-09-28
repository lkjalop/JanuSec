"""Repository for playbook executions."""
from __future__ import annotations
from typing import Any, Dict, List
from db.database import fetch, with_retry
import json

INSERT = """
INSERT INTO playbook_executions (alert_id, category, playbook_id, actions, status, error)
VALUES ($1,$2,$3,$4::jsonb,$5,$6)
RETURNING id, created_at
"""

RECENT = """
SELECT id, created_at, alert_id, category, playbook_id, actions, status, error
FROM playbook_executions
ORDER BY created_at DESC
LIMIT $1
"""

async def insert_execution(alert_id: int | None, category: str, playbook_id: str, actions: list[str], status: str, error: str | None):
    async def _do():
        return await fetch(INSERT, alert_id, category, playbook_id, json.dumps(actions), status, error)
    row = await with_retry(_do)
    return dict(row) if row else None

async def list_recent(limit: int = 100) -> List[Dict[str, Any]]:
    rows = await fetch(RECENT, limit)
    return [dict(r) for r in rows]

__all__ = ['insert_execution','list_recent']
