"""Events Repository"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from db.database import execute, fetchrow, with_retry

INSERT_EVENT = """
INSERT INTO events (id, source, event_type, severity, ts_original, raw_payload, tenant_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO UPDATE SET
    source = EXCLUDED.source,
    event_type = EXCLUDED.event_type,
    severity = EXCLUDED.severity,
    ts_original = EXCLUDED.ts_original,
    raw_payload = EXCLUDED.raw_payload,
    tenant_id = COALESCE(EXCLUDED.tenant_id, events.tenant_id)
"""

GET_EVENT = "SELECT * FROM events WHERE id=$1 AND (tenant_id=$2 OR (tenant_id IS NULL AND $2 IS NULL))"

async def upsert_event(event: dict[str, Any], tenant_id: str | None):
    """Insert or update an event scoped to a tenant.

    Enforces object ownership: if an event with the same id already exists
    under a different tenant, reject the write to prevent cross-tenant updates.
    """
    async def _do():
        # Ownership check: if row exists with a different tenant, block
        try:
            existing = await fetchrow("SELECT tenant_id FROM events WHERE id=$1", event.get('id'))
            if existing is not None:
                existing_tid = existing.get('tenant_id') if isinstance(existing, dict) else existing['tenant_id']
                if existing_tid != tenant_id:
                    raise PermissionError('cross_tenant_write_rejected')
        except Exception as _e:
            # Propagate explicit permission errors; ignore missing table in lite mode
            if isinstance(_e, PermissionError):
                raise
        return await execute(
            INSERT_EVENT,
            event.get('id'),
            event.get('source'),
            event.get('event_type'),
            event.get('severity'),
            event.get('timestamp'),
            json.dumps(event.get('details', {})),
            tenant_id
        )
    return await with_retry(_do)

async def get_event(event_id: str, tenant_id: str | None) -> dict[str, Any] | None:
    row = await fetchrow(GET_EVENT, event_id, tenant_id)
    return dict(row) if row else None
