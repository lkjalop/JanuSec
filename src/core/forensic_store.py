import os
import sqlite3
import threading
import time
import json
from typing import Optional

DEFAULT_DB = os.environ.get('FORENSIC_DB_PATH', 'artifacts/forensics.sqlite')


class ForensicStore:
    """Simple store for forensic artifact metadata and chain-of-custody.

    For production, replace with Postgres/DynamoDB and an index suitable for queries.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = path or DEFAULT_DB
        os.makedirs(os.path.dirname(self.path), exist_ok=True) if os.path.dirname(self.path) else None
        self._lock = threading.RLock()
        self._ensure_schema()

    def _conn(self):
        return sqlite3.connect(self.path)

    def _ensure_schema(self):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute('''
        CREATE TABLE IF NOT EXISTS forensic_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            s3_url TEXT,
            collector TEXT,
            collected_at INTEGER,
            sha256 TEXT,
            meta TEXT
        )
        ''')
        conn.commit()
        conn.close()

    def insert_artifact(self, s3_url: str, collector: str, collected_at: int, sha256: str, meta: Optional[dict] = None):
        with self._lock:
            conn = self._conn()
            cur = conn.cursor()
            cur.execute('INSERT INTO forensic_artifacts(s3_url,collector,collected_at,sha256,meta) VALUES (?,?,?,?,?)',
                        (s3_url, collector, collected_at, sha256, json.dumps(meta or {})))
            conn.commit()
            conn.close()
