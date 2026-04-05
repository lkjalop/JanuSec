"""Write a clean UTF-8 idempotency.py file atomically.

This script writes the canonical module bytes to the target path using
binary mode to avoid accidental encoding/bom issues.
"""
from pathlib import Path

content = '''from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, Optional


def compute_idempotency_id(*parts: str) -> str:
    raw = '|'.join(parts)
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


class IdempotencyStore:
    """Idempotency store with in-memory default and optional SQLite backing.

    This implementation is intentionally small: by default it uses an in-memory
    dict. If `db_path` is provided, a lightweight SQLite schema will be used
    to persist processed keys and replays.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._mem: Dict[str, Dict[str, Any]] = {}
        if self.db_path:
            # lazy-create schema
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                'CREATE TABLE IF NOT EXISTS processed (key TEXT PRIMARY KEY, fingerprint TEXT, meta TEXT, processed_at REAL)'
            )
            conn.execute(
                'CREATE TABLE IF NOT EXISTS replays (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, fingerprint TEXT, actor TEXT, outcome TEXT, extra TEXT, ts REAL)'
            )
            conn.commit()
            conn.close()

    def _conn(self) -> sqlite3.Connection:
        if not self.db_path:
            raise RuntimeError('SQLite backing not configured')
        return sqlite3.connect(self.db_path, timeout=5)

    def is_processed(self, key: Optional[str] = None, fingerprint: Optional[str] = None) -> bool:
        if self.db_path:
            with self._conn() as c:
                if key:
                    cur = c.execute('SELECT 1 FROM processed WHERE key = ? LIMIT 1', (key,))
                    return cur.fetchone() is not None
                if fingerprint:
                    cur = c.execute('SELECT 1 FROM processed WHERE fingerprint = ? LIMIT 1', (fingerprint,))
                    return cur.fetchone() is not None
                return False
        if key and key in self._mem:
            return True
        if fingerprint:
            return any(v.get('fingerprint') == fingerprint for v in self._mem.values())
        return False

    def mark_processed(self, key: str, fingerprint: str, meta: Optional[Dict[str, Any]] = None) -> bool:
        meta_json = json.dumps(meta or {})
        ts = time.time()
        if self.db_path:
            with self._lock:
                with self._conn() as c:
                    cur = c.execute('SELECT 1 FROM processed WHERE key = ? OR fingerprint = ? LIMIT 1', (key, fingerprint))
                    if cur.fetchone():
                        return False
                    c.execute('INSERT INTO processed (key, fingerprint, meta, processed_at) VALUES (?, ?, ?, ?)', (key, fingerprint, meta_json, ts))
                    return True
        with self._lock:
            if key in self._mem or any(v.get('fingerprint') == fingerprint for v in self._mem.values()):
                return False
            self._mem[key] = {'fingerprint': fingerprint, 'meta': meta or {}, 'processed_at': ts}
            return True

    def record_replay(self, key: str, fingerprint: str, actor: str, outcome: str, extra: Optional[Dict[str, Any]] = None) -> None:
        extra_json = json.dumps(extra or {})
        ts = time.time()
        if self.db_path:
            with self._conn() as c:
                c.execute('INSERT INTO replays (key, fingerprint, actor, outcome, extra, ts) VALUES (?, ?, ?, ?, ?, ?)', (key, fingerprint, actor, outcome, extra_json, ts))
            return
        with self._lock:
            rec = self._mem.get(key)
            if rec is not None:
                rec.setdefault('_replays', []).append({'actor': actor, 'outcome': outcome, 'extra': extra or {}, 'ts': ts})


def run_idempotent(store: IdempotencyStore, key: str, func: Callable[[], Any]) -> Any:
    """Execute `func` once per `key`. If already processed, return stored result if available."""
    if store.is_processed(key=key):
        # try to return the stored result if present in memory (or in DB meta)
        try:
            if not store.db_path:
                rec = getattr(store, '_mem', {}).get(key)
                if rec:
                    return rec.get('meta', {}).get('last_result')
            else:
                with store._conn() as c:
                    cur = c.execute('SELECT meta FROM processed WHERE key = ? LIMIT 1', (key,))
                    r = cur.fetchone()
                    if r and r[0]:
                        m = json.loads(r[0])
                        return m.get('last_result')
        except Exception:
            return None
        return None
    res = func()
    try:
        fp = hashlib.sha256(json.dumps(res, default=str).encode('utf-8')).hexdigest()
        # try to store result in meta for retrieval on duplicates
        store.mark_processed(key, fp, meta={'last_result': res})
    except Exception:
        # ignore serialization or store errors
        pass
    return res
'''

target = Path('src/core/idempotency.py')
target.parent.mkdir(parents=True, exist_ok=True)
# write atomically by writing to temp then renaming
tmp = target.with_suffix('.tmp')
tmp.write_bytes(content.encode('utf-8'))
tmp.replace(target)
print('WROTE', target)
