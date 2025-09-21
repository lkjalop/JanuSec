"""Alerts Repository"""
from __future__ import annotations
import json
from typing import Any, Dict
from db.database import execute, with_retry, fetch

INSERT_ALERT = """
INSERT INTO alerts (event_id, verdict, confidence, severity, factors, playbook_result)
VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb)
"""
LIST_RECENT = "SELECT * FROM alerts ORDER BY created_at DESC LIMIT $1"

async def insert_alert(event_id: str, verdict: str, confidence: float, severity: str, factors, playbook_result):
    async def _do():
        return await execute(
            INSERT_ALERT,
            event_id,
            verdict,
            confidence,
            severity,
            json.dumps(factors),
            json.dumps(playbook_result)
        )
    return await with_retry(_do)

async def list_recent(limit: int = 50):
    rows = await fetch(LIST_RECENT, limit)
    return [dict(r) for r in rows]
