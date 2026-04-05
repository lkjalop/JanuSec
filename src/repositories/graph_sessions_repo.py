from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

from src.db.database import DatabaseNotAvailable, get_pool


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS graph_sessions (
    session_id TEXT PRIMARY KEY,
    tenant_id TEXT,
    status TEXT,
    start_ts REAL,
    end_ts REAL,
    query_params_json TEXT,
    summary_json TEXT NOT NULL,
    snapshot_ref TEXT,
    evidence_refs_json TEXT,
    paths_json TEXT,
    scores_json TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
)
"""


async def _acquire_conn():
    pool = await get_pool()
    return pool.acquire()


def _is_sqlite_conn(conn: Any) -> bool:
    return conn.__class__.__name__ == "SQLiteConnectionProxy"


async def ensure_schema() -> None:
    async with await _acquire_conn() as conn:
        await conn.execute(_SCHEMA_SQL)


async def upsert_graph_session(record: Dict[str, Any]) -> None:
    await ensure_schema()
    now = float(record.get("updated_at") or time.time())
    created_at = float(record.get("created_at") or now)
    args = (
        str(record.get("session_id") or ""),
        record.get("tenant_id"),
        record.get("status"),
        record.get("start_ts"),
        record.get("end_ts"),
        json.dumps(record.get("query_params") or {}),
        json.dumps(record.get("summary") or {}),
        record.get("graph_snapshot_ref"),
        json.dumps(record.get("evidence_refs") or []),
        json.dumps(record.get("paths") or []),
        json.dumps(record.get("scores") or {}),
        created_at,
        now,
    )
    async with await _acquire_conn() as conn:
        if _is_sqlite_conn(conn):
            sql = """
            INSERT INTO graph_sessions(
                session_id, tenant_id, status, start_ts, end_ts,
                query_params_json, summary_json, snapshot_ref, evidence_refs_json,
                paths_json, scores_json, created_at, updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(session_id) DO UPDATE SET
                tenant_id=excluded.tenant_id,
                status=excluded.status,
                start_ts=excluded.start_ts,
                end_ts=excluded.end_ts,
                query_params_json=excluded.query_params_json,
                summary_json=excluded.summary_json,
                snapshot_ref=excluded.snapshot_ref,
                evidence_refs_json=excluded.evidence_refs_json,
                paths_json=excluded.paths_json,
                scores_json=excluded.scores_json,
                updated_at=excluded.updated_at
            """
        else:
            sql = """
            INSERT INTO graph_sessions(
                session_id, tenant_id, status, start_ts, end_ts,
                query_params_json, summary_json, snapshot_ref, evidence_refs_json,
                paths_json, scores_json, created_at, updated_at
            ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            ON CONFLICT(session_id) DO UPDATE SET
                tenant_id=EXCLUDED.tenant_id,
                status=EXCLUDED.status,
                start_ts=EXCLUDED.start_ts,
                end_ts=EXCLUDED.end_ts,
                query_params_json=EXCLUDED.query_params_json,
                summary_json=EXCLUDED.summary_json,
                snapshot_ref=EXCLUDED.snapshot_ref,
                evidence_refs_json=EXCLUDED.evidence_refs_json,
                paths_json=EXCLUDED.paths_json,
                scores_json=EXCLUDED.scores_json,
                updated_at=EXCLUDED.updated_at
            """
        await conn.execute(sql, *args)


def _decode_row(row: Dict[str, Any]) -> Dict[str, Any]:
    def _loads(value: Any, default: Any) -> Any:
        if value in (None, ""):
            return default
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except Exception:
            return default

    return {
        "session_id": row.get("session_id"),
        "tenant_id": row.get("tenant_id"),
        "status": row.get("status"),
        "start_ts": row.get("start_ts"),
        "end_ts": row.get("end_ts"),
        "query_params": _loads(row.get("query_params_json"), {}),
        "summary": _loads(row.get("summary_json"), {}),
        "graph_snapshot_ref": row.get("snapshot_ref"),
        "evidence_refs": _loads(row.get("evidence_refs_json"), []),
        "paths": _loads(row.get("paths_json"), []),
        "scores": _loads(row.get("scores_json"), {}),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


async def get_graph_session(session_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    await ensure_schema()
    async with await _acquire_conn() as conn:
        if tenant_id:
            row = await conn.fetchrow(
                "SELECT * FROM graph_sessions WHERE session_id=$1 AND (tenant_id=$2 OR tenant_id IS NULL)",
                session_id,
                tenant_id,
            )
        else:
            row = await conn.fetchrow("SELECT * FROM graph_sessions WHERE session_id=$1", session_id)
    if not row:
        return None
    if not isinstance(row, dict):
        row = dict(row)
    return _decode_row(row)


__all__ = [
    "DatabaseNotAvailable",
    "ensure_schema",
    "get_graph_session",
    "upsert_graph_session",
]
