"""Alerts Repository"""
from __future__ import annotations

import json
from typing import Any, Dict

from db.database import execute, fetch, with_retry

INSERT_ALERT = """
INSERT INTO alerts (event_id, verdict, confidence, severity, factors, playbook_result, tenant_id)
VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7)
"""
LIST_RECENT = "SELECT * FROM alerts WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL)) ORDER BY created_at DESC LIMIT $2"

async def insert_alert(event_id: str, verdict: str, confidence: float, severity: str, factors, playbook_result, tenant_id: str | None):
    async def _do():
        return await execute(
            INSERT_ALERT,
            event_id,
            verdict,
            confidence,
            severity,
            json.dumps(factors),
            json.dumps(playbook_result),
            tenant_id
        )
    return await with_retry(_do)

async def list_recent(limit: int = 50, tenant_id: str | None = None):
    rows = await fetch(LIST_RECENT, tenant_id, limit)
    return [dict(r) for r in rows]
