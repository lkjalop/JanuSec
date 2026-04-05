"""Incidents repository: stores analyst incidents with metadata including attack_subgraph.

Provides DB-backed helpers (upsert/get/list) and falls back to an in-memory store when the DB
adapter is not available (useful for tests/local runs).
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

_IN_MEMORY: List[Dict[str, Any]] = []

try:
    from db.database import execute, fetchrow, fetch, with_retry
except Exception:
    execute = None  # type: ignore
    fetchrow = None  # type: ignore
    fetch = None  # type: ignore
    with_retry = None  # type: ignore


CREATE_INCIDENTS_TABLE = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    artifact_id TEXT,
    title TEXT,
    severity TEXT,
    status TEXT DEFAULT 'open',
    summary TEXT,
    tags JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    tenant_id TEXT
);
"""


async def upsert_incident(incident_id: str, payload: Dict[str, Any], tenant_id: Optional[str] = None) -> None:
    """Insert or update an incident row in DB if DB adapter available, otherwise store in memory."""
    # Normalize metadata and tags
    metadata = payload.get('metadata') or {}
    tags = payload.get('tags') or []
    title = payload.get('title')
    severity = payload.get('severity') or 'medium'
    status = payload.get('status') or 'open'
    summary = payload.get('summary') or payload.get('description')
    artifact_id = payload.get('artifact_id') or payload.get('event_id')

    if execute and with_retry:
        INSERT = """
        INSERT INTO incidents (id, artifact_id, title, severity, status, summary, tags, metadata, tenant_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9)
        ON CONFLICT (id) DO UPDATE SET
            artifact_id=EXCLUDED.artifact_id,
            title=EXCLUDED.title,
            severity=EXCLUDED.severity,
            status=EXCLUDED.status,
            summary=EXCLUDED.summary,
            tags=EXCLUDED.tags,
            metadata=EXCLUDED.metadata,
            tenant_id=COALESCE(EXCLUDED.tenant_id, incidents.tenant_id)
        """

        async def _do():
            # Ownership check: existing row with different tenant must not be updated
            try:
                row = await fetchrow("SELECT tenant_id FROM incidents WHERE id=$1", incident_id)
                if row is not None:
                    existing_tid = row.get('tenant_id') if isinstance(row, dict) else row['tenant_id']
                    if existing_tid != tenant_id:
                        raise PermissionError('cross_tenant_write_rejected')
            except Exception as _e:
                if isinstance(_e, PermissionError):
                    raise
            return await execute(
                INSERT,
                incident_id,
                artifact_id,
                title,
                severity,
                status,
                summary,
                json.dumps(tags),
                json.dumps(metadata),
                tenant_id,
            )

        return await with_retry(_do)

    # Fallback in-memory
    rec = {
        'id': incident_id,
        'artifact_id': artifact_id,
        'title': title,
        'severity': severity,
        'status': status,
        'summary': summary,
        'tags': tags,
        'metadata': metadata,
        'created_at': time.time(),
        'tenant_id': tenant_id,
    }
    _IN_MEMORY.append(rec)


async def get_incident(incident_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    # Only attempt DB-backed read when the full DB adapter is available (execute + with_retry).
    # This mirrors the upsert_incident guard so tests that monkeypatch DB adapters (execute/with_retry)
    # will correctly fall back to the in-memory store.
    if execute and with_retry:
        Q = "SELECT * FROM incidents WHERE id=$1 AND (tenant_id=$2 OR (tenant_id IS NULL AND $2 IS NULL))"

        async def _do():
            row = await fetchrow(Q, incident_id, tenant_id)
            return dict(row) if row else None

        return await with_retry(_do)

    # Fallback search in-memory
    for r in reversed(_IN_MEMORY):
        if r.get('id') == incident_id and (tenant_id is None or r.get('tenant_id') == tenant_id):
            return r
    return None


async def list_incidents(limit: int = 50, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    # Only attempt DB-backed listing when the full DB adapter is available (execute + with_retry).
    # Use with_retry to mirror the write path and ensure test monkeypatches can force the
    # in-memory fallback by clearing execute/with_retry.
    if execute and with_retry:
        Q = "SELECT * FROM incidents WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL)) ORDER BY created_at DESC LIMIT $2"

        async def _do():
            rows = await fetch(Q, tenant_id, limit)
            return [dict(r) for r in rows]

        return await with_retry(_do)

    # Fallback in-memory
    if tenant_id is None:
        return list(reversed(_IN_MEMORY))[:limit]
    filtered = [r for r in reversed(_IN_MEMORY) if r.get('tenant_id') == tenant_id]
    return filtered[:limit]


def list_memory() -> List[Dict[str, Any]]:
    return list(_IN_MEMORY)


__all__ = ['upsert_incident', 'get_incident', 'list_incidents', 'list_memory', 'CREATE_INCIDENTS_TABLE']
