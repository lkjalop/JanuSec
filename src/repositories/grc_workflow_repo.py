"""Append-only repository for analyst GRC workflow events."""

from __future__ import annotations

import json
import time
from typing import Any

from src.db.database import DatabaseNotAvailable, get_pool, init_pool


async def _connection():
    try:
        pool = await get_pool()
    except DatabaseNotAvailable:
        await init_pool()
        pool = await get_pool()
    return pool.acquire()


def _sqlite(conn: Any) -> bool:
    return conn.__class__.__name__ == "SQLiteConnectionProxy"


async def ensure_schema() -> None:
    async with await _connection() as conn:
        json_type = "TEXT" if _sqlite(conn) else "JSONB"
        timestamp = "REAL NOT NULL" if _sqlite(conn) else "TIMESTAMPTZ NOT NULL DEFAULT NOW()"
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS grc_workflow_events (
              event_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, assessment_id TEXT NOT NULL,
              case_id TEXT NOT NULL, finding_id TEXT NOT NULL, event_type TEXT NOT NULL,
              content_hash TEXT NOT NULL, record_json {json_type} NOT NULL, appended_at {timestamp})
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_grc_workflow_scope ON "
            "grc_workflow_events(tenant_id,assessment_id,case_id,finding_id,appended_at)"
        )


async def append_event(event: dict[str, Any]) -> dict[str, Any]:
    await ensure_schema()
    payload = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    values = tuple(str(event.get(key) or "") for key in (
        "event_id", "tenant_id", "assessment_id", "case_id", "finding_id", "event_type", "content_hash",
    ))
    if not all(values):
        raise ValueError("complete_grc_event_required")
    async with await _connection() as conn:
        existing = await conn.fetchrow("SELECT record_json FROM grc_workflow_events WHERE event_id=$1", values[0])
        if existing:
            old = dict(existing)["record_json"]
            old = old if isinstance(old, str) else json.dumps(old, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if old != payload:
                raise ValueError("append_only_grc_event_conflict")
            return {"event_id": values[0], "appended": False}
        if _sqlite(conn):
            await conn.execute(
                "INSERT INTO grc_workflow_events(event_id,tenant_id,assessment_id,case_id,finding_id,event_type,content_hash,record_json,appended_at) VALUES(?,?,?,?,?,?,?,?,?)",
                *values, payload, time.time(),
            )
        else:
            await conn.execute(
                "INSERT INTO grc_workflow_events(event_id,tenant_id,assessment_id,case_id,finding_id,event_type,content_hash,record_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb)",
                *values, payload,
            )
    return {"event_id": values[0], "appended": True}


async def list_events(tenant_id: str, assessment_id: str, case_id: str) -> list[dict[str, Any]]:
    await ensure_schema()
    async with await _connection() as conn:
        rows = await conn.fetch(
            "SELECT record_json FROM grc_workflow_events WHERE tenant_id=$1 AND assessment_id=$2 AND case_id=$3 ORDER BY appended_at,event_id",
            tenant_id, assessment_id, case_id,
        )
    result = []
    for row in rows:
        value = dict(row)["record_json"]
        result.append(value if isinstance(value, dict) else json.loads(value))
    return result


__all__ = ["append_event", "ensure_schema", "list_events"]
