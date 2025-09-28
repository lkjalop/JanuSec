"""Audit Log Repository"""
from __future__ import annotations
import json
from typing import Any, Dict, Optional
from db.database import execute, fetchrow, fetch, with_retry
import os
from typing import List

# In-memory fallback ring buffer when DB disabled or errors occur
_INMEM_AUDIT: List[dict] = []
_INMEM_MAX = 500

def _push_inmem(entry: dict):
    _INMEM_AUDIT.append(entry)
    if len(_INMEM_AUDIT) > _INMEM_MAX:
        del _INMEM_AUDIT[0:len(_INMEM_AUDIT)-_INMEM_MAX]

def get_inmem_chain(event_id: str):  # diagnostic helper (tests / debug only)
    return [e for e in _INMEM_AUDIT if e.get('event_id') == event_id]

INSERT_AUDIT = """
INSERT INTO audit_log (event_id, action, details, custody_hash, prev_hash, tenant_id)
VALUES ($1,$2,$3::jsonb,$4,$5,$6)
RETURNING id, custody_hash
"""

GET_LAST_AUDIT = """
SELECT custody_hash FROM audit_log WHERE event_id=$1 AND (tenant_id=$2 OR (tenant_id IS NULL AND $2 IS NULL)) ORDER BY id DESC LIMIT 1
"""
GET_CHAIN = """
SELECT id, action, custody_hash, prev_hash, created_at, details
FROM audit_log WHERE event_id=$1 AND (tenant_id=$2 OR (tenant_id IS NULL AND $2 IS NULL)) ORDER BY id ASC
"""

async def append_audit(event_id: str, action: str, details: Dict[str, Any], custody_hash: str, prev_hash: str | None, tenant_id: str | None):
    entry = {
        'event_id': event_id,
        'action': action,
        'details': details,
        'custody_hash': custody_hash,
        'prev_hash': prev_hash,
        'tenant_id': tenant_id
    }
    disable_db = os.getenv('DISABLE_DB','0').lower() in ('1','true','yes')
    debug = os.getenv('CUSTODY_DEBUG','0').lower() in ('1','true','yes') or os.getenv('FAST_TEST_MODE','0').lower() in ('1','true','yes')
    if disable_db:
        _push_inmem(entry)
        if debug:
            print(f"[CUSTODY][INMEM] {event_id} action={action} custody_hash={custody_hash[:8]} prev={prev_hash[:8] if prev_hash else None}")
        return entry
    try:
        async def _do():
            return await fetchrow(INSERT_AUDIT, event_id, action, json.dumps(details), custody_hash, prev_hash, tenant_id)
        row = await with_retry(_do)
        rec = dict(row) if row else entry
        # Still mirror to in-memory for test assertions
        _push_inmem(entry)
        if debug:
            print(f"[CUSTODY][DB] {event_id} action={action} custody_hash={custody_hash[:8]} prev={prev_hash[:8] if prev_hash else None}")
        return rec
    except Exception:
        # Fallback silently to in-memory
        _push_inmem(entry)
        if debug:
            print(f"[CUSTODY][FALLBACK] {event_id} action={action} custody_hash={custody_hash[:8]} prev={prev_hash[:8] if prev_hash else None}")
        return entry

async def get_last_hash(event_id: str, tenant_id: str | None) -> Optional[str]:
    disable_db = os.getenv('DISABLE_DB','0').lower() in ('1','true','yes')
    if disable_db:
        chain = get_inmem_chain(event_id)
        return chain[-1]['custody_hash'] if chain else None
    try:
        row = await fetchrow(GET_LAST_AUDIT, event_id, tenant_id)
        return row['custody_hash'] if row else None
    except Exception:
        chain = get_inmem_chain(event_id)
        return chain[-1]['custody_hash'] if chain else None

async def get_chain(event_id: str, tenant_id: str | None):
    rows = await fetch(GET_CHAIN, event_id, tenant_id)
    return [dict(r) for r in rows]
