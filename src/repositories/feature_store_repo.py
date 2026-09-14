import json
import time
from typing import Optional, Dict

DB_PATH = 'data/app.db'


try:
    import aiosqlite  # type: ignore
    _HAS_AIOSQLITE = True
except Exception:
    import sqlite3
    import asyncio
    _HAS_AIOSQLITE = False


class FeatureStoreRepo:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_PATH

    async def init_db(self):
        if _HAS_AIOSQLITE:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute('''
                CREATE TABLE IF NOT EXISTS feature_store (
                    id TEXT PRIMARY KEY,
                    event_ts INTEGER NOT NULL,
                    tenant_id TEXT,
                    event_json TEXT NOT NULL
                )
                ''')
                await db.commit()
        else:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS feature_store (
                    id TEXT PRIMARY KEY,
                    event_ts INTEGER NOT NULL,
                    tenant_id TEXT,
                    event_json TEXT NOT NULL
                )
            ''')
            conn.commit()
            conn.close()

    async def write(self, id: str, event: Dict):
        now = int(time.time())
        payload = json.dumps(event)
        if _HAS_AIOSQLITE:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    'INSERT OR REPLACE INTO feature_store(id,event_ts,tenant_id,event_json) VALUES (?,?,?,?)',
                    (id, now, event.get('tenant_id'), payload),
                )
                await db.commit()
        else:
            loop = asyncio.get_event_loop()
            def _run():
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute('INSERT OR REPLACE INTO feature_store(id,event_ts,tenant_id,event_json) VALUES (?,?,?,?)', (id, now, event.get('tenant_id'), payload))
                conn.commit()
                conn.close()
            await loop.run_in_executor(None, _run)

    async def get(self, id: str) -> Optional[Dict]:
        if _HAS_AIOSQLITE:
            async with aiosqlite.connect(self.db_path) as db:
                cur = await db.execute('SELECT event_json FROM feature_store WHERE id=?', (id,))
                row = await cur.fetchone()
                if not row:
                    return None
                return json.loads(row[0])
        else:
            loop = asyncio.get_event_loop()
            def _run():
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute('SELECT event_json FROM feature_store WHERE id=?', (id,))
                row = cur.fetchone()
                conn.close()
                return row
            row = await loop.run_in_executor(None, _run)
            if not row:
                return None
            return json.loads(row[0])

    async def list_recent(self, limit: int = 500):
        out = []
        if _HAS_AIOSQLITE:
            async with aiosqlite.connect(self.db_path) as db:
                cur = await db.execute('SELECT id, event_json, event_ts FROM feature_store ORDER BY event_ts DESC LIMIT ?', (limit,))
                rows = await cur.fetchall()
                for r in rows:
                    try:
                        obj = json.loads(r[1])
                    except Exception:
                        obj = {}
                    out.append({'id': r[0], 'event_ts': r[2], 'event': obj})
        else:
            loop = asyncio.get_event_loop()
            def _run():
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute('SELECT id, event_json, event_ts FROM feature_store ORDER BY event_ts DESC LIMIT ?', (limit,))
                rows = cur.fetchall()
                conn.close()
                return rows
            rows = await loop.run_in_executor(None, _run)
            for r in rows:
                try:
                    obj = json.loads(r[1])
                except Exception:
                    obj = {}
                out.append({'id': r[0], 'event_ts': r[2], 'event': obj})
        return out
