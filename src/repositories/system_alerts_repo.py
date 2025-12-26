"""Repository for system alerts (guardrail emissions)."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from db.database import execute, fetch, with_retry

INSERT = """
INSERT INTO system_alerts (tenant_id, category, severity, message, details, dedupe_hash)
VALUES ($1,$2,$3,$4,$5::jsonb,$6)
RETURNING id
"""

RECENT = """
SELECT id, created_at, tenant_id, category, severity, message, details, acknowledged
FROM system_alerts
WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL))
ORDER BY created_at DESC
LIMIT $2
"""

ACK = """UPDATE system_alerts SET acknowledged=TRUE WHERE id=$1 RETURNING id"""

async def insert_alert(tenant_id: str | None, category: str, severity: str, message: str, details: dict[str, Any], dedupe_hash: str | None):
    async def _do():
        return await fetch(INSERT, tenant_id, category, severity, message, json.dumps(details), dedupe_hash)
    row = await with_retry(_do)
    return dict(row) if row else None

async def list_recent(tenant_id: str | None, limit: int = 50) -> list[dict[str, Any]]:
    rows = await fetch(RECENT, tenant_id, limit)
    return [dict(r) for r in rows]

async def acknowledge(alert_id: int):
    row = await fetch(ACK, alert_id)
    return bool(row)
