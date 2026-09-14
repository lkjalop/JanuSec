"""Append-only persistence for outbound GRC dispatch receipts."""

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
            CREATE TABLE IF NOT EXISTS grc_dispatch_receipts (
              content_hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, assessment_id TEXT NOT NULL,
              case_id TEXT NOT NULL, target TEXT NOT NULL, idempotency_key TEXT NOT NULL,
              record_json {json_type} NOT NULL, appended_at {timestamp})
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_grc_dispatch_scope ON "
            "grc_dispatch_receipts(tenant_id,assessment_id,case_id,target,appended_at)"
        )
        await conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_grc_dispatch_idempotency ON "
            "grc_dispatch_receipts(tenant_id,assessment_id,case_id,target,idempotency_key)"
        )


def _record(row: Any) -> dict[str, Any] | None:
    if not row:
        return None
    value = dict(row)["record_json"]
    return value if isinstance(value, dict) else json.loads(value)


async def get_receipt_by_idempotency(
    *, tenant_id: str, assessment_id: str, case_id: str, target: str, idempotency_key: str,
) -> dict[str, Any] | None:
    await ensure_schema()
    async with await _connection() as conn:
        row = await conn.fetchrow(
            "SELECT record_json FROM grc_dispatch_receipts WHERE tenant_id=$1 AND assessment_id=$2 "
            "AND case_id=$3 AND target=$4 AND idempotency_key=$5",
            tenant_id, assessment_id, case_id, target, idempotency_key,
        )
    return _record(row)


async def list_receipts(
    *, tenant_id: str, assessment_id: str, case_id: str,
) -> list[dict[str, Any]]:
    await ensure_schema()
    async with await _connection() as conn:
        rows = await conn.fetch(
            "SELECT record_json FROM grc_dispatch_receipts WHERE tenant_id=$1 AND assessment_id=$2 "
            "AND case_id=$3 ORDER BY appended_at,content_hash",
            tenant_id, assessment_id, case_id,
        )
    return [record for row in rows if (record := _record(row)) is not None]


async def append_receipt(*, tenant_id: str, assessment_id: str, case_id: str, receipt: dict[str, Any]) -> bool:
    await ensure_schema()
    content_hash = str(receipt.get("content_hash") or "")
    target, idempotency_key = str(receipt.get("target") or ""), str(receipt.get("idempotency_key") or "")
    if not all((tenant_id, assessment_id, case_id, content_hash, target, idempotency_key)):
        raise ValueError("complete_grc_dispatch_receipt_required")
    payload = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    async with await _connection() as conn:
        existing = await conn.fetchrow("SELECT record_json FROM grc_dispatch_receipts WHERE content_hash=$1", content_hash)
        if existing:
            old = dict(existing)["record_json"]
            old = old if isinstance(old, str) else json.dumps(old, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if old != payload:
                raise ValueError("append_only_grc_dispatch_conflict")
            return False
        values = (content_hash, tenant_id, assessment_id, case_id, target, idempotency_key, payload)
        if _sqlite(conn):
            await conn.execute(
                "INSERT INTO grc_dispatch_receipts(content_hash,tenant_id,assessment_id,case_id,target,idempotency_key,record_json,appended_at) VALUES(?,?,?,?,?,?,?,?)",
                *values, time.time(),
            )
        else:
            await conn.execute(
                "INSERT INTO grc_dispatch_receipts(content_hash,tenant_id,assessment_id,case_id,target,idempotency_key,record_json) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)",
                *values,
            )
    return True


__all__ = [
    "append_receipt", "ensure_schema", "get_receipt_by_idempotency", "list_receipts",
]
