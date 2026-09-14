import json
import os
import sqlite3
import time
import math
from typing import Optional, Dict, Any, List

DB_PATH = os.path.join(os.getcwd(), 'data', 'dispatch_outbox.db')

def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH, timeout=10)

def _ensure_db():
    conn = _connect()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS outbox (
        id TEXT PRIMARY KEY,
        tenant_id TEXT,
        endpoint TEXT,
        payload TEXT,
        attempts INTEGER DEFAULT 0,
        last_error TEXT,
        status TEXT DEFAULT 'pending',
        created_ts INTEGER,
        updated_ts INTEGER
    )
    ''')
    conn.commit()
    conn.close()

def enqueue(dispatch_id: str, tenant_id: str, endpoint: str, payload: Dict[str, Any]):
    _ensure_db()
    now = int(time.time())
    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute('''INSERT OR REPLACE INTO outbox (id, tenant_id, endpoint, payload, attempts, status, created_ts, updated_ts)
                       VALUES (?, ?, ?, ?, COALESCE((select attempts from outbox where id=?), 0), 'pending', ?, ?)''',
                    (dispatch_id, tenant_id, endpoint, json.dumps(payload), dispatch_id, now, now))
        conn.commit()
    finally:
        conn.close()

def mark_attempt(dispatch_id: str, attempts: int, last_error: Optional[str], status: str = 'pending'):
    now = int(time.time())
    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute('UPDATE outbox SET attempts=?, last_error=?, status=?, updated_ts=? WHERE id=?',
                    (attempts, last_error, status, now, dispatch_id))
        conn.commit()
    finally:
        conn.close()

def get_pending(limit: int = 10) -> List[Dict[str, Any]]:
    _ensure_db()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM outbox WHERE status='pending' ORDER BY created_ts LIMIT ?", (limit,))
        rows = cur.fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        out.append({k: r[k] for k in r.keys()})
    return out

def get_by_id(dispatch_id: str) -> Optional[Dict[str, Any]]:
    _ensure_db()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute('SELECT * FROM outbox WHERE id=?', (dispatch_id,))
        r = cur.fetchone()
    finally:
        conn.close()
    if not r:
        return None
    return {k: r[k] for k in r.keys()}

def list_failed(limit: int = 50) -> List[Dict[str, Any]]:
    _ensure_db()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM outbox WHERE status='failed' ORDER BY updated_ts DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
    finally:
        conn.close()
    return [{k: r[k] for k in r.keys()} for r in rows]

def compute_backoff(attempts: int, base: float = 1.0, cap: float = 300.0, jitter: float = 0.1) -> float:
    # exponential backoff with jitter
    try:
        exp = base * (2 ** max(0, attempts - 1))
        wait = min(exp, cap)
        # jitter fraction of wait
        jitter_amt = wait * jitter
        return max(0.1, wait - jitter_amt) + (jitter_amt * 2 * (0.5))
    except Exception:
        return base

def repair(dispatch_id: str):
    """Repair a failed outbox entry: reset attempts to 0 and status to pending."""
    _ensure_db()
    conn = _connect()
    try:
        cur = conn.cursor()
        cur.execute('UPDATE outbox SET attempts=0, status="pending", last_error=NULL, updated_ts=? WHERE id=?', (int(time.time()), dispatch_id))
        conn.commit()
    finally:
        conn.close()

def mark_done(dispatch_id: str):
    mark_attempt(dispatch_id, attempts=0, last_error=None, status='done')
