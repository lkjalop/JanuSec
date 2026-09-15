"""Append-only persistence for signed IAM, topology, and CMDB snapshots."""

from __future__ import annotations

import json
import time
from typing import Any

from src.core.evidence_contract.records import canonical_hash
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
            CREATE TABLE IF NOT EXISTS infrastructure_truth_snapshots (
              snapshot_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, kind TEXT NOT NULL,
              source TEXT NOT NULL, version TEXT NOT NULL, valid_from TEXT NOT NULL,
              valid_to TEXT, receipt_hash TEXT NOT NULL, payload_hash TEXT NOT NULL,
              record_json {json_type} NOT NULL, appended_at {timestamp})
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_infrastructure_truth_scope "
            "ON infrastructure_truth_snapshots(tenant_id,kind,appended_at)"
        )


async def append_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    receipt = snapshot.get("snapshot_receipt") if isinstance(snapshot.get("snapshot_receipt"), dict) else {}
    tenant_id = str(receipt.get("tenant_id") or "")
    kind = str(receipt.get("kind") or "")
    receipt_hash = str(receipt.get("receipt_hash") or "")
    if not tenant_id or kind not in {
        "iam", "topology", "cmdb", "data_classification",
        "regulatory_applicability", "control_verification",
    } or not receipt_hash:
        raise ValueError("valid_signed_infrastructure_snapshot_required")
    snapshot_id = f"infra_{receipt_hash}"
    payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    content_hash = canonical_hash(snapshot)
    await ensure_schema()
    async with await _connection() as conn:
        existing = await conn.fetchrow(
            "SELECT receipt_hash,record_json FROM infrastructure_truth_snapshots WHERE snapshot_id=$1",
            snapshot_id,
        )
        if existing:
            old = dict(existing)
            old_payload = old.get("record_json")
            if not isinstance(old_payload, str):
                old_payload = json.dumps(old_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if old.get("receipt_hash") != receipt_hash or old_payload != payload:
                raise ValueError("append_only_infrastructure_snapshot_conflict")
            return {"snapshot_id": snapshot_id, "appended": False, "content_hash": content_hash}
        values = (
            snapshot_id, tenant_id, kind, str(receipt.get("source") or "unknown"),
            str(receipt.get("version") or "unknown"), str(receipt.get("valid_from") or ""),
            receipt.get("valid_to"), receipt_hash, str(receipt.get("payload_hash") or ""), payload,
        )
        if _sqlite(conn):
            await conn.execute(
                "INSERT INTO infrastructure_truth_snapshots(snapshot_id,tenant_id,kind,source,version,valid_from,valid_to,receipt_hash,payload_hash,record_json,appended_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)", *values, time.time(),
            )
        else:
            await conn.execute(
                "INSERT INTO infrastructure_truth_snapshots(snapshot_id,tenant_id,kind,source,version,valid_from,valid_to,receipt_hash,payload_hash,record_json) "
                "VALUES($1,$2,$3,$4,$5,$6::timestamptz,$7::timestamptz,$8,$9,$10::jsonb)", *values,
            )
    return {"snapshot_id": snapshot_id, "appended": True, "content_hash": content_hash}


async def latest_snapshot(tenant_id: str, kind: str) -> dict[str, Any] | None:
    if not tenant_id or kind not in {
        "iam", "topology", "cmdb", "data_classification",
        "regulatory_applicability", "control_verification",
    }:
        raise ValueError("infrastructure_snapshot_scope_required")
    await ensure_schema()
    async with await _connection() as conn:
        row = await conn.fetchrow(
            "SELECT record_json FROM infrastructure_truth_snapshots WHERE tenant_id=$1 AND kind=$2 "
            "ORDER BY appended_at DESC LIMIT 1", tenant_id, kind,
        )
    if not row:
        return None
    value = dict(row)["record_json"]
    return value if isinstance(value, dict) else json.loads(value)


async def list_snapshots(
    tenant_id: str, kind: str, *, limit: int = 1000,
) -> list[dict[str, Any]]:
    if not tenant_id or kind not in {
        "iam", "topology", "cmdb", "data_classification",
        "regulatory_applicability", "control_verification",
    }:
        raise ValueError("infrastructure_snapshot_scope_required")
    await ensure_schema()
    async with await _connection() as conn:
        rows = await conn.fetch(
            "SELECT record_json FROM infrastructure_truth_snapshots WHERE tenant_id=$1 AND kind=$2 "
            "ORDER BY appended_at DESC LIMIT $3", tenant_id, kind, max(1, min(limit, 10000)),
        )
    result = []
    for row in rows:
        value = dict(row)["record_json"]
        result.append(value if isinstance(value, dict) else json.loads(value))
    return result


__all__ = ["append_snapshot", "ensure_schema", "latest_snapshot", "list_snapshots"]
