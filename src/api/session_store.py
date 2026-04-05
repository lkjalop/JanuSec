from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


def get_session_ttl_seconds() -> int:
    try:
        return int(os.getenv('SESSION_TTL_SECONDS', '86400') or 86400)
    except Exception:
        return 86400


class BaseSessionStore:
    def save(self, session_id: str, summary: Dict[str, Any]) -> None:  # pragma: no cover (interface)
        raise NotImplementedError

    def load(self, session_id: str) -> Optional[Dict[str, Any]]:  # pragma: no cover (interface)
        raise NotImplementedError

    def cleanup(self, ttl_seconds: Optional[int] = None) -> None:  # pragma: no cover (interface)
        raise NotImplementedError


class JsonSessionStore(BaseSessionStore):
    def __init__(self, dir_path: Optional[str] = None) -> None:
        self.dir = Path(dir_path or os.getenv('SESSION_PERSIST_DIR', 'data/sessions'))
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def _path(self, session_id: str) -> Path:
        return self.dir / f"{session_id}.json"

    def save(self, session_id: str, summary: Dict[str, Any]) -> None:
        record = {'session_id': session_id, 'summary': summary}
        path = self._path(session_id)
        tmp = path.with_suffix('.tmp')
        lock = path.with_suffix('.lock')
        try:
            # simple lock file to reduce cross-process races (best-effort)
            for _ in range(5):
                try:
                    # atomic creation: fail if exists
                    fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    os.close(fd)
                    break
                except FileExistsError:
                    time.sleep(0.02)
            with tmp.open('w', encoding='utf8') as fh:
                json.dump(record, fh)
            tmp.replace(path)
        except Exception:
            try:
                # best-effort fallback
                with path.open('w', encoding='utf8') as fh:
                    json.dump(record, fh)
            except Exception:
                pass
        finally:
            try:
                if lock.exists():
                    lock.unlink()
            except Exception:
                pass

    def load(self, session_id: str) -> Optional[Dict[str, Any]]:
        path = self._path(session_id)
        if not path.exists():
            return None
        ttl = get_session_ttl_seconds()
        try:
            age = time.time() - path.stat().st_mtime
            if age > ttl:
                return None
            with path.open('r', encoding='utf8') as fh:
                return json.load(fh)
        except Exception:
            return None

    def cleanup(self, ttl_seconds: Optional[int] = None) -> None:
        ttl = ttl_seconds or get_session_ttl_seconds()
        now = time.time()
        try:
            for p in self.dir.glob('*.json'):
                try:
                    if (now - p.stat().st_mtime) > ttl:
                        p.unlink(missing_ok=True)
                except Exception:
                    pass
        except Exception:
            pass


class SqliteSessionStore(BaseSessionStore):
    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or os.getenv('SESSION_PERSIST_SQLITE_PATH', 'data/sessions/sessions.db')
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path, timeout=10)
            cur = conn.cursor()
            cur.execute(
                "CREATE TABLE IF NOT EXISTS sessions(\n"
                " id TEXT PRIMARY KEY,\n"
                " json TEXT NOT NULL,\n"
                " created_at REAL NOT NULL,\n"
                " updated_at REAL NOT NULL\n"
                ")"
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_updated_at ON sessions(updated_at)")
            conn.commit()
            conn.close()
        except Exception:
            pass

    def save(self, session_id: str, summary: Dict[str, Any]) -> None:
        import sqlite3
        payload = json.dumps({'session_id': session_id, 'summary': summary})
        now = time.time()
        backoff = 0.05
        for attempt in range(4):
            try:
                if attempt == 0:
                    self._ensure_schema()
                try:
                    pass
                except Exception:
                    pass
                conn = sqlite3.connect(self.db_path, timeout=10)
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO sessions(id,json,created_at,updated_at) VALUES(?,?,?,?)\n"
                    "ON CONFLICT(id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at",
                    (session_id, payload, now, now),
                )
                conn.commit()
                conn.close()
                return
            except sqlite3.OperationalError:
                time.sleep(backoff)
                backoff = min(0.5, backoff * 2)
                self._ensure_schema()
            except Exception:
                break

    def load(self, session_id: str) -> Optional[Dict[str, Any]]:
        try:
            import sqlite3
            self._ensure_schema()
            ttl = get_session_ttl_seconds()
            cutoff = time.time() - ttl
            conn = sqlite3.connect(self.db_path, timeout=10)
            cur = conn.cursor()
            cur.execute("SELECT json, updated_at FROM sessions WHERE id=?", (session_id,))
            row = cur.fetchone()
            conn.close()
            try:
                pass
            except Exception:
                pass
            if not row:
                return None
            js, updated = row
            if updated is not None and updated < cutoff:
                return None
            try:
                return json.loads(js)
            except Exception:
                return None
        except Exception:
            return None

    def cleanup(self, ttl_seconds: Optional[int] = None) -> None:
        try:
            import sqlite3
            self._ensure_schema()
            ttl = ttl_seconds or get_session_ttl_seconds()
            cutoff = time.time() - ttl
            conn = sqlite3.connect(self.db_path, timeout=10)
            cur = conn.cursor()
            cur.execute("DELETE FROM sessions WHERE updated_at < ?", (cutoff,))
            conn.commit()
            conn.close()
        except Exception:
            pass


_STORE: BaseSessionStore | None = None
_BACKEND_NAME: str | None = None


def get_session_store() -> BaseSessionStore:
    global _STORE
    global _BACKEND_NAME
    backend = (os.getenv('SESSION_BACKEND', 'json') or 'json').lower()
    if _STORE is not None and _BACKEND_NAME == backend:
        return _STORE
    if backend == 'sqlite':
        _STORE = SqliteSessionStore()
    else:
        _STORE = JsonSessionStore()
    _BACKEND_NAME = backend
    return _STORE

def reset_session_store() -> None:
    global _STORE, _BACKEND_NAME
    _STORE = None
    _BACKEND_NAME = None
