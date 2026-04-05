import sqlite3
import threading
import json
import os
from typing import Optional, Dict, Any, List


DB_SCHEMA = '''
CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,
    provider TEXT,
    payload TEXT,
    expires_at TEXT,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_tenant ON subscriptions(tenant_id);
'''


class SubscriptionStore:
    """Simple SQLite-backed subscription store. Safe for multiple readers/writers
    across threads/processes when used with WAL mode. Keeps a tiny abstraction
    for listing, saving, deleting, and renewing subscriptions.
    """

    def __init__(self, db_path: str = 'data/subscriptions.db'):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('PRAGMA journal_mode=WAL;')
            cur = conn.cursor()
            for stmt in DB_SCHEMA.split(';'):
                s = stmt.strip()
                if s:
                    cur.execute(s)
            conn.commit()
        finally:
            conn.close()

    def _conn(self):
        c = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        return c

    def save(self, sub_id: str, tenant_id: str, provider: str, payload: Dict[str, Any], expires_at: Optional[str] = None, created_at: Optional[str] = None):
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    'REPLACE INTO subscriptions (id, tenant_id, provider, payload, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)',
                    (sub_id, tenant_id, provider, json.dumps(payload), expires_at, created_at),
                )
                conn.commit()
            finally:
                conn.close()

    def get(self, sub_id: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        try:
            cur = conn.execute('SELECT id, tenant_id, provider, payload, expires_at, created_at FROM subscriptions WHERE id=?', (sub_id,))
            row = cur.fetchone()
            if not row:
                return None
            return {
                'id': row[0],
                'tenant_id': row[1],
                'provider': row[2],
                'payload': json.loads(row[3]) if row[3] else {},
                'expires_at': row[4],
                'created_at': row[5],
            }
        finally:
            conn.close()

    def delete(self, sub_id: str):
        with self._lock:
            conn = self._conn()
            try:
                conn.execute('DELETE FROM subscriptions WHERE id=?', (sub_id,))
                conn.commit()
            finally:
                conn.close()

    def list_for_tenant(self, tenant_id: str) -> List[Dict[str, Any]]:
        conn = self._conn()
        try:
            cur = conn.execute('SELECT id, tenant_id, provider, payload, expires_at, created_at FROM subscriptions WHERE tenant_id=?', (tenant_id,))
            rows = cur.fetchall()
            return [
                {
                    'id': r[0],
                    'tenant_id': r[1],
                    'provider': r[2],
                    'payload': json.loads(r[3]) if r[3] else {},
                    'expires_at': r[4],
                    'created_at': r[5],
                }
                for r in rows
            ]
        finally:
            conn.close()

    def all(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        try:
            cur = conn.execute('SELECT id, tenant_id, provider, payload, expires_at, created_at FROM subscriptions')
            rows = cur.fetchall()
            return [
                {
                    'id': r[0],
                    'tenant_id': r[1],
                    'provider': r[2],
                    'payload': json.loads(r[3]) if r[3] else {},
                    'expires_at': r[4],
                    'created_at': r[5],
                }
                for r in rows
            ]
        finally:
            conn.close()
