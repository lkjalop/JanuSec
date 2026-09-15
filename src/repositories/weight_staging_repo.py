import json
import time
from typing import Optional, Dict

DB_PATH = 'data/app.db'


try:
    import aiosqlite  # type: ignore
    _HAS_AIOSQLITE = True
except Exception:
    import sqlite3
    import functools
    import asyncio

    _HAS_AIOSQLITE = False

    class _AioSqliteFallback:
        def __init__(self, path):
            self._path = path

        async def execute(self, query, params=()):
            loop = asyncio.get_event_loop()
            def _run():
                conn = sqlite3.connect(self._path)
                cur = conn.cursor()
                cur.execute(query, params)
                conn.commit()
                cur.close()
                conn.close()
            return await loop.run_in_executor(None, _run)

        async def fetchall(self, query, params=()):
            loop = asyncio.get_event_loop()
            def _run():
                conn = sqlite3.connect(self._path)
                cur = conn.cursor()
                cur.execute(query, params)
                rows = cur.fetchall()
                cur.close()
                conn.close()
                return rows
            return await loop.run_in_executor(None, _run)

    # Provide minimal aiosqlite.connect shim
    class _aiosqlite_connect_shim:
        def __init__(self, path):
            self._path = path

        async def __aenter__(self):
            return _AioSqliteFallback(self._path)

        async def __aexit__(self, exc_type, exc, tb):
            return False

    def _aiosqlite_connect(path):
        return _aiosqlite_connect_shim(path)


class WeightStagingRepo:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_PATH

    async def init_db(self):
        if _HAS_AIOSQLITE:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute('''
                CREATE TABLE IF NOT EXISTS weight_staging (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    proposed_weights_json TEXT NOT NULL,
                    created_ts INTEGER NOT NULL,
                    applied INTEGER NOT NULL DEFAULT 0
                )
                ''')
                await db.commit()
        else:
            # synchronous fallback
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS weight_staging (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    proposed_weights_json TEXT NOT NULL,
                    created_ts INTEGER NOT NULL,
                    applied INTEGER NOT NULL DEFAULT 0
                )
            ''')
            conn.commit()
            conn.close()

    async def stage(self, rule_id: str, weights: Dict):
        now = int(time.time())
        payload = json.dumps(weights)
        if _HAS_AIOSQLITE:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    'INSERT INTO weight_staging(rule_id,proposed_weights_json,created_ts,applied) VALUES (?,?,?,0)',
                    (rule_id, payload, now),
                )
                await db.commit()
        else:
            loop = asyncio.get_event_loop()
            def _run():
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute('INSERT INTO weight_staging(rule_id,proposed_weights_json,created_ts,applied) VALUES (?,?,?,0)', (rule_id, payload, now))
                conn.commit()
                conn.close()
            await loop.run_in_executor(None, _run)

    async def list_pending(self):
        if _HAS_AIOSQLITE:
            async with aiosqlite.connect(self.db_path) as db:
                cur = await db.execute('SELECT id,rule_id,proposed_weights_json,created_ts FROM weight_staging WHERE applied=0')
                rows = await cur.fetchall()
                return [{'id': r[0], 'rule_id': r[1], 'weights': json.loads(r[2]), 'created_ts': r[3]} for r in rows]
        else:
            loop = asyncio.get_event_loop()
            def _run():
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute('SELECT id,rule_id,proposed_weights_json,created_ts FROM weight_staging WHERE applied=0')
                rows = cur.fetchall()
                conn.close()
                return rows
            rows = await loop.run_in_executor(None, _run)
            return [{'id': r[0], 'rule_id': r[1], 'weights': json.loads(r[2]), 'created_ts': r[3]} for r in rows]

    async def mark_applied(self, id: int):
        if _HAS_AIOSQLITE:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute('UPDATE weight_staging SET applied=1 WHERE id=?', (id,))
                await db.commit()
        else:
            loop = asyncio.get_event_loop()
            def _run():
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute('UPDATE weight_staging SET applied=1 WHERE id=?', (id,))
                conn.commit()
                conn.close()
            await loop.run_in_executor(None, _run)
