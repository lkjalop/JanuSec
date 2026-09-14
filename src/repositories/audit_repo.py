"""Audit repository utilities.

This module now serves two adjacent responsibilities:

1. Report routing audit records (persisted to a lightweight SQLite DB).
2. Chain-of-custody append-only logs used by the orchestrator during alerting.

The report audit functions (insert/list/update) remain synchronous and
best-effort, while the custody helpers are async-friendly so the pipeline can
`await append_audit(...)` without blocking.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import time
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

_DB_PATH = Path('data') / 'audits.db'
_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Chain-of-custody globals
_CHAIN_LOG_PATH = Path(os.getenv('CUSTODY_CHAIN_PATH', 'data/chain_of_custody.jsonl'))
_CHAIN_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
_CHAIN_MAX = max(32, int(os.getenv('CUSTODY_CHAIN_MAXLEN', '512')))
_CHAIN_LOCK = Lock()
_INMEM_CHAINS: dict[str, deque[dict[str, Any]]] = {}


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _ensure() -> None:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            '''
        CREATE TABLE IF NOT EXISTS report_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT,
            persona TEXT,
            recipients TEXT,
            disclosure_level INTEGER,
            note TEXT,
            sent_by TEXT,
            sent_at REAL
        )
        '''
        )
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Report audit helpers (delivery queue, report actions)
# ---------------------------------------------------------------------------
def insert_audit(audit: Dict[str, Any]) -> int:
    _ensure()
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            '''INSERT INTO report_audit (report_id, persona, recipients, disclosure_level, note, sent_by, sent_at) VALUES (?,?,?,?,?,?,?)''',
            (
                audit.get('report_id'),
                audit.get('persona'),
                json.dumps(audit.get('recipients') or []),
                int(audit.get('disclosure_level') or 0),
                audit.get('note'),
                audit.get('sent_by'),
                float(audit.get('sent_at') or 0),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_audits(limit: int = 50) -> List[Dict[str, Any]]:
    _ensure()
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute('SELECT id, report_id, persona, recipients, disclosure_level, note, sent_by, sent_at FROM report_audit ORDER BY sent_at DESC LIMIT ?', (limit,))
        rows = cur.fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    'id': r['id'],
                    'report_id': r['report_id'],
                    'persona': r['persona'],
                    'recipients': json.loads(r['recipients'] or '[]'),
                    'disclosure_level': r['disclosure_level'],
                    'note': r['note'],
                    'sent_by': r['sent_by'],
                    'sent_at': r['sent_at'],
                }
            )
        return out
    finally:
        conn.close()


def update_audit_status(audit_id: int, status: str, details: Dict[str, Any] | None = None) -> bool:
    _ensure()
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute('UPDATE report_audit SET note = COALESCE(note, \'\') || ? WHERE id = ?', (f"\nstatus:{status} details:{json.dumps(details or {})}", audit_id))
        conn.commit()
        return True
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Chain-of-custody helpers
# ---------------------------------------------------------------------------
def _sanitize_details(details: Dict[str, Any] | None) -> Dict[str, Any]:
    if details is None:
        return {}
    if not isinstance(details, dict):
        return {'value': repr(details)}
    sanitized: Dict[str, Any] = {}
    for key, value in details.items():
        try:
            json.dumps(value)
            sanitized[key] = value
        except TypeError:
            sanitized[key] = repr(value)
    return sanitized


def _get_chain(event_id: str) -> deque[dict[str, Any]]:
    chain = _INMEM_CHAINS.get(event_id)
    if chain is None:
        chain = deque(maxlen=_CHAIN_MAX)
        _INMEM_CHAINS[event_id] = chain
    return chain


def _persist_chain_entry(entry: dict[str, Any]) -> None:
    try:
        with _CHAIN_LOG_PATH.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(entry, separators=(',', ':')) + '\n')
    except Exception:
        # Disk writes are best-effort; tests assert in-memory behavior
        pass


async def append_audit(
    event_id: str,
    action: str,
    details: Dict[str, Any] | None,
    custody_hash: Optional[str],
    prev_hash: Optional[str],
    tenant_id: str | None = None,
) -> None:
    """Append a custody audit entry (best-effort persistence)."""
    eid = str(event_id)
    entry = {
        'event_id': eid,
        'tenant_id': tenant_id,
        'action': action,
        'details': _sanitize_details(details),
        'custody_hash': custody_hash,
        'prev_hash': prev_hash,
        'ts': time.time(),
    }
    with _CHAIN_LOCK:
        chain = _get_chain(eid)
        if entry['prev_hash'] is None and chain:
            entry['prev_hash'] = chain[-1].get('custody_hash')
        chain.append(entry.copy())

    try:
        await asyncio.to_thread(_persist_chain_entry, entry)
    except RuntimeError:
        _persist_chain_entry(entry)


async def get_last_hash(event_id: str, tenant_id: str | None = None) -> Optional[str]:
    """Return the most recent custody hash for an event (in-memory or disk fallback)."""
    eid = str(event_id)
    with _CHAIN_LOCK:
        chain = _INMEM_CHAINS.get(eid)
        if chain:
            for item in reversed(chain):
                if tenant_id and item.get('tenant_id') not in (tenant_id, None):
                    continue
                return item.get('custody_hash')

    # Disk fallback: scan log for last entry (best-effort; O(n) in log size)
    if not _CHAIN_LOG_PATH.exists():
        return None
    last_hash: Optional[str] = None
    try:
        with _CHAIN_LOG_PATH.open('r', encoding='utf-8') as handle:
            for line in handle:
                try:
                    obj = json.loads(line.strip())
                except Exception:
                    continue
                if obj.get('event_id') != eid:
                    continue
                if tenant_id and obj.get('tenant_id') not in (tenant_id, None):
                    continue
                last_hash = obj.get('custody_hash')
    except Exception:
        return None
    return last_hash


def get_inmem_chain(event_id: str) -> List[Dict[str, Any]]:
    """Return a copy of the in-memory custody chain for tests/inspection."""
    eid = str(event_id)
    with _CHAIN_LOCK:
        chain = list(_INMEM_CHAINS.get(eid) or [])
        return [dict(item) for item in reversed(chain)]


def reset_inmem_chain_for_tests() -> None:
    """Utility for tests to clear the in-memory chain."""
    with _CHAIN_LOCK:
        _INMEM_CHAINS.clear()


__all__ = [
    'insert_audit',
    'list_audits',
    'update_audit_status',
    'append_audit',
    'get_last_hash',
    'get_inmem_chain',
    'reset_inmem_chain_for_tests',
]
