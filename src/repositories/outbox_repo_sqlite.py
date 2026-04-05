"""SQLite-backed outbox repository.

Provides durable enqueue and background retry support for the dispatcher.
Schema (created on first use):
  outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    connector TEXT NOT NULL,
    tenant_id TEXT,
    event_id TEXT,
    payload_json TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    next_retry REAL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
  )
Unique logical key: (connector, tenant_id, event_id)
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List

_DB_PATH = os.getenv('OUTBOX_SQLITE_PATH', 'artifacts/outbox/outbox.db')


def _get_conn() -> sqlite3.Connection:
    p = Path(_DB_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS outbox (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          connector TEXT NOT NULL,
          tenant_id TEXT,
          event_id TEXT,
          payload_json TEXT,
          attempts INTEGER NOT NULL DEFAULT 0,
          last_error TEXT,
          next_retry REAL,
          created_at REAL NOT NULL,
          updated_at REAL NOT NULL,
          UNIQUE(connector, tenant_id, event_id)
        );
        """
    )
    conn.commit()


def enqueue(connector: str, tenant_id: str | None, event_id: str | None, payload: Dict[str, Any] | None = None, delay_seconds: float | None = None) -> int:
    now = time.time()
    nr = (now + float(delay_seconds)) if delay_seconds else None
    payload_json = json.dumps(payload or {})
    with _get_conn() as conn:
        try:
            cur = conn.execute(
                'INSERT INTO outbox(connector, tenant_id, event_id, payload_json, attempts, next_retry, created_at, updated_at) VALUES(?,?,?,?,0,?,?,?)',
                (connector, tenant_id, event_id, payload_json, nr, now, now)
            )
            conn.commit()
            return int(cur.lastrowid)
        except sqlite3.IntegrityError:
            # already exists; update payload and next_retry
            conn.execute(
                'UPDATE outbox SET payload_json=?, updated_at=?, next_retry=? WHERE connector=? AND COALESCE(tenant_id,"")=COALESCE(?,"") AND COALESCE(event_id,"")=COALESCE(?,"")',
                (payload_json, now, nr, connector, tenant_id, event_id)
            )
            conn.commit()
            # fetch id
            cur = conn.execute('SELECT id FROM outbox WHERE connector=? AND COALESCE(tenant_id,"")=COALESCE(?,"") AND COALESCE(event_id,"")=COALESCE(?,"")', (connector, tenant_id, event_id))
            row = cur.fetchone()
            return int(row['id']) if row else 0


def next_pending(limit: int = 10, max_attempts: int = 3) -> List[Dict[str, Any]]:
    now = time.time()
    with _get_conn() as conn:
        cur = conn.execute(
            'SELECT * FROM outbox WHERE attempts < ? AND (next_retry IS NULL OR next_retry <= ?) ORDER BY created_at ASC LIMIT ?',
            (int(max_attempts), now, int(limit))
        )
        rows = [dict(r) for r in cur.fetchall()]
        # claim by bumping attempts and next_retry to a short future
        claim_until = now + 30.0
        for r in rows:
            conn.execute('UPDATE outbox SET attempts = attempts + 1, updated_at=?, next_retry=? WHERE id=?', (now, claim_until, int(r['id'])))
        conn.commit()
        return rows


def mark_done(row_id: int) -> None:
    with _get_conn() as conn:
        conn.execute('DELETE FROM outbox WHERE id=?', (int(row_id),))
        conn.commit()


def mark_done_by_key(connector: str, tenant_id: str | None, event_id: str | None) -> None:
    with _get_conn() as conn:
        conn.execute('DELETE FROM outbox WHERE connector=? AND COALESCE(tenant_id,"")=COALESCE(?,"") AND COALESCE(event_id,"")=COALESCE(?,"")', (connector, tenant_id, event_id))
        conn.commit()


def fail(row_id: int, error: str | None = None, retry_in: float | None = None) -> None:
    now = time.time()
    nr = (now + float(retry_in)) if retry_in else (now + 60.0)
    with _get_conn() as conn:
        conn.execute('UPDATE outbox SET last_error=?, next_retry=?, updated_at=? WHERE id=?', (error, nr, now, int(row_id)))
        conn.commit()
