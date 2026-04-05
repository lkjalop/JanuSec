"""
Simple DLQ audit repository using SQLite via the project's database helper when available,
falling back to a local JSONL file when DB isn't configured.

Provides: init_table(), insert_audit(entry: dict) -> id, list_audits(limit, offset)
"""
from __future__ import annotations
import os
import json
import time
from typing import List, Dict, Any, Optional
try:
    from src.db import database as _db
except Exception:
    _db = None

TABLE_NAME = 'arc_dlq_replay_audit'

async def init_table():
    if _db is None:
        return
    try:
        pool = await _db.get_pool()
    except Exception:
        return
    sql = f'''
    CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        req_id TEXT,
        idx INTEGER,
        actor TEXT,
        note TEXT,
        ts INTEGER
    )
    '''
    try:
        await _db.execute(sql)
    except Exception:
        # best-effort
        pass


def _jsonl_path():
    d = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, 'arc_dlq_replay_audit.jsonl')


async def insert_audit(entry: Dict[str, Any]) -> Optional[int]:
    """Insert an audit entry. Returns DB id if available, else None."""
    if _db is not None:
        try:
            ts = int(entry.get('ts', time.time()))
            action = entry.get('action')
            req_id = entry.get('req_id')
            idx = entry.get('index')
            actor = entry.get('actor')
            note = entry.get('note')
            sql = f"INSERT INTO {TABLE_NAME}(action, req_id, idx, actor, note, ts) VALUES ($1,$2,$3,$4,$5,$6)"
            try:
                await _db.execute(sql, action, req_id, idx, actor, note, ts)
                return None
            except Exception:
                # try alt placeholder style
                try:
                    alt = sql.replace('$1', '?').replace('$2', '?').replace('$3', '?').replace('$4', '?').replace('$5', '?').replace('$6', '?')
                    await _db.execute(alt, action, req_id, idx, actor, note, ts)
                    return None
                except Exception:
                    pass
        except Exception:
            pass
    # fallback to JSONL append
    try:
        p = _jsonl_path()
        with open(p, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(entry) + '\n')
    except Exception:
        pass
    return None


async def list_audits(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    if _db is not None:
        try:
            rows = await _db.fetch(f"SELECT id, action, req_id, idx, actor, note, ts FROM {TABLE_NAME} ORDER BY ts DESC LIMIT $1 OFFSET $2", limit, offset)
            return [dict(r) for r in rows]
        except Exception:
            pass
    # fallback JSONL
    p = _jsonl_path()
    out = []
    try:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8') as fh:
                lines = fh.read().splitlines()
                for line in lines[::-1][offset: offset + limit]:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        continue
    except Exception:
        pass
    return out
