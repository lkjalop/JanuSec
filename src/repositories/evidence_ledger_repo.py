"""Append-only evidence/assertion/stage ledger with exact tenant/case reads."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any

from src.core.evidence_contract.metrics import EVIDENCE_APPEND
from src.db.database import DatabaseNotAvailable, get_pool, init_pool

_SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS evidence_ledger (
    record_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    record_json TEXT NOT NULL,
    appended_at REAL NOT NULL
)
"""
_SCHEMA_POSTGRES = """
CREATE TABLE IF NOT EXISTS evidence_ledger (
    record_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    case_id TEXT NOT NULL,
    record_type TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    record_json JSONB NOT NULL,
    appended_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""
_INDEX = "CREATE INDEX IF NOT EXISTS idx_evidence_ledger_scope ON evidence_ledger(tenant_id, case_id, appended_at)"


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
        await conn.execute(_SCHEMA_SQLITE if _sqlite(conn) else _SCHEMA_POSTGRES)
        await conn.execute(_INDEX)


def _identity(record: Mapping[str, Any]) -> tuple[str, str, str, str, str]:
    record_type = str(record.get("record_type") or "").strip()
    id_field = {
        "evidence": "evidence_id",
        "assertion": "assertion_id",
        "stage_manifest": "manifest_hash",
        "stage_invocation": "invocation_id",
        "stage_artifact": "artifact_id",
        "artifact_receipt": "receipt_id",
        "assessment_dag": "dag_id",
        "stage_status": "status_id",
        "evidence_pack": "pack_id",
    }.get(record_type)
    record_id = str(record.get(id_field or "") or "").strip()
    tenant_id = str(record.get("tenant_id") or "").strip()
    case_id = str(record.get("case_id") or "").strip()
    content_hash = str(record.get("content_hash") or record.get("manifest_hash") or record.get("dag_id") or "").strip()
    if not all((record_type, record_id, tenant_id, case_id, content_hash)):
        raise ValueError("ledger_record_missing_identity")
    return record_id, tenant_id, case_id, record_type, content_hash


async def append(record: Mapping[str, Any]) -> bool:
    """Append a record; identical replay is idempotent, divergence is rejected."""
    await ensure_schema()
    record_id, tenant_id, case_id, record_type, content_hash = _identity(record)
    payload = json.dumps(dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    async with await _connection() as conn:
        existing = await conn.fetchrow(
            "SELECT content_hash, record_json FROM evidence_ledger WHERE record_id=$1", record_id
        )
        if existing:
            existing = dict(existing)
            if existing.get("content_hash") != content_hash or existing.get("record_json") != payload:
                EVIDENCE_APPEND.labels(record_type, "conflict").inc()
                raise ValueError("append_only_ledger_conflict")
            EVIDENCE_APPEND.labels(record_type, "idempotent").inc()
            return False
        if _sqlite(conn):
            args = (record_id, tenant_id, case_id, record_type, content_hash, payload, time.time())
            sql = (
                "INSERT INTO evidence_ledger("
                "record_id,tenant_id,case_id,record_type,content_hash,record_json,appended_at"
                ") VALUES(?,?,?,?,?,?,?)"
            )
        else:
            args = (record_id, tenant_id, case_id, record_type, content_hash, payload)
            sql = (
                "INSERT INTO evidence_ledger("
                "record_id,tenant_id,case_id,record_type,content_hash,record_json,appended_at"
                ") VALUES($1,$2,$3,$4,$5,$6::jsonb,NOW())"
            )
        await conn.execute(sql, *args)
        EVIDENCE_APPEND.labels(record_type, "success").inc()
    return True


async def append_many(records: list[Mapping[str, Any]]) -> int:
    count = 0
    for record in records:
        count += int(await append(record))
    return count


async def list_case(
    tenant_id: str, case_id: str, *, record_type: str | None = None, limit: int = 2000
) -> list[dict[str, Any]]:
    if not tenant_id or not case_id:
        raise ValueError("tenant_and_case_required")
    await ensure_schema()
    args: tuple[Any, ...] = (tenant_id, case_id, max(1, min(limit, 10000)))
    query = (
        "SELECT record_json FROM evidence_ledger WHERE tenant_id=$1 AND case_id=$2 ORDER BY appended_at ASC LIMIT $3"
    )
    if record_type:
        args = (tenant_id, case_id, record_type, max(1, min(limit, 10000)))
        query = (
            "SELECT record_json FROM evidence_ledger "
            "WHERE tenant_id=$1 AND case_id=$2 AND record_type=$3 "
            "ORDER BY appended_at ASC LIMIT $4"
        )
    async with await _connection() as conn:
        rows = await conn.fetch(query, *args)
    decoded = []
    for row in rows:
        value = dict(row)["record_json"]
        decoded.append(value if isinstance(value, dict) else json.loads(value))
    return decoded


__all__ = ["append", "append_many", "ensure_schema", "list_case"]
