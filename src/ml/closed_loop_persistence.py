import os
import sqlite3
from datetime import datetime
from typing import Optional, Dict, Any, List

DB_PATH = os.getenv('CLOSED_LOOP_DB_PATH', 'data/precision_metrics.db')


def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)


def _ensure_tables():
    conn = _conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS factor_weight_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            candidate_json TEXT,
            delta_summary TEXT,
            created_at TEXT,
            approved_at TEXT,
            approved_by TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS factor_weight_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            payload TEXT,
            actor TEXT,
            ts TEXT
        )
        """
    )
    conn.commit()
    conn.close()


async def persist_candidate(payload: Dict[str, Any]) -> int:
    _ensure_tables()
    import json
    candidate = json.dumps(payload.get('candidate') or payload)
    summary = payload.get('summary') or ''
    created_at = payload.get('created_at') or datetime.utcnow().isoformat()
    # Prefer project DB adapter when available
    try:
        from db.adapter import execute as db_execute
        # Use Postgres-style params and RETURNING id
        sql = "INSERT INTO factor_weight_candidates (candidate_json, delta_summary, created_at) VALUES ($1,$2,$3) RETURNING id"
        # If running inside an event loop, await the async execute
        import asyncio
        if asyncio.get_event_loop().is_running():
            res = await db_execute(sql, candidate, summary, created_at)
            # db_execute for asyncpg returns a Record or similar; try fetch id
            try:
                if isinstance(res, int):
                    return res
            except Exception:
                pass
        else:
            # run in a new event loop
            import asyncio as _async
            res = _async.run(db_execute(sql, candidate, summary, created_at))
    except Exception:
        # fallback to sqlite file-backed persistence
        conn = _conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO factor_weight_candidates (candidate_json, delta_summary, created_at) VALUES (?,?,?)",
                    (candidate, summary, created_at))
        cid = cur.lastrowid
        conn.commit()
        conn.close()
        return cid
    # Unable to extract id; return -1 to indicate unknown id for async path
    return -1


async def persist_audit(action: str, payload: Any, actor: str = 'system') -> int:
    _ensure_tables()
    import json
    pl = json.dumps(payload, default=str)
    ts = datetime.utcnow().isoformat()
    try:
        from db.adapter import execute as db_execute
        import asyncio
        if asyncio.get_event_loop().is_running():
            await db_execute("INSERT INTO factor_weight_audit (action,payload,actor,ts) VALUES ($1,$2,$3,$4)", action, pl, actor, ts)
            return -1
        else:
            import asyncio as _async
            _async.run(db_execute("INSERT INTO factor_weight_audit (action,payload,actor,ts) VALUES ($1,$2,$3,$4)", action, pl, actor, ts))
            return -1
    except Exception:
        conn = _conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO factor_weight_audit (action,payload,actor,ts) VALUES (?,?,?,?)",
                    (action, pl, actor, ts))
        aid = cur.lastrowid
        conn.commit()
        conn.close()
        return aid


def list_candidates(limit: int = 50) -> List[Dict[str, Any]]:
    _ensure_tables()
    # Use sqlite fallback for synchronous listing
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT id,candidate_json,delta_summary,created_at,approved_at,approved_by FROM factor_weight_candidates ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    import json
    out = []
    for r in rows:
        try:
            cand = json.loads(r[1])
        except Exception:
            cand = r[1]
        out.append({'id': r[0], 'candidate': cand, 'summary': r[2], 'created_at': r[3], 'approved_at': r[4], 'approved_by': r[5]})
    return out


async def approve_candidate_db(candidate_id: int, actor: str, applied: Dict[str, float]) -> None:
    _ensure_tables()
    try:
        from db.adapter import execute as db_execute
        import asyncio
        if asyncio.get_event_loop().is_running():
            await db_execute("UPDATE factor_weight_candidates SET approved_at=$1, approved_by=$2 WHERE id=$3", datetime.utcnow().isoformat(), actor, candidate_id)
            return
        else:
            import asyncio as _async
            _async.run(db_execute("UPDATE factor_weight_candidates SET approved_at=$1, approved_by=$2 WHERE id=$3", datetime.utcnow().isoformat(), actor, candidate_id))
            return
    except Exception:
        conn = _conn()
        cur = conn.cursor()
        cur.execute("UPDATE factor_weight_candidates SET approved_at=?, approved_by=? WHERE id=?", (datetime.utcnow().isoformat(), actor, candidate_id))
        conn.commit()
        conn.close()
        return
"""Async persistence helpers for closed-loop manager using database_adapter.

Provides async functions `persist_candidate` and `persist_audit` that attempt to
use the platform's `database_adapter.db_manager` to write structured JSON into
Postgres (via NeonPostgreSQLAdapter). When DB isn't available, functions
fall back to writing JSONL into `data/` as a safe fallback.

This file keeps the async DB integration isolated so `ClosedLoopManager` can
call into it synchronously via helper runners when necessary.
"""
import os
import json
import asyncio
from typing import Dict, Any

try:
    import database_adapter
    DB_AVAILABLE = True
except Exception:
    DB_AVAILABLE = False


async def persist_candidate_async(candidate: Dict[str, Any]):
    """Persist candidate record into platform DB (async) or JSONL fallback.

    Candidate shape: {candidate: {..weights..}, summary: str, created_at: ts}
    """
    if DB_AVAILABLE and hasattr(database_adapter.db_manager, 'adapter') and database_adapter.db_manager.adapter:
        adapter = database_adapter.db_manager.adapter
        # Attempt postgres path when pool available
        try:
            if hasattr(adapter, 'pool') and adapter.pool:
                async with adapter.pool.acquire() as conn:
                    row = await conn.fetchrow(
                        """
                        INSERT INTO factor_weight_candidates (candidate_json, delta_summary, created_at)
                        VALUES ($1, $2, $3)
                        RETURNING id
                        """,
                        json.dumps(candidate), candidate.get('summary'), candidate.get('created_at')
                    )
                    try:
                        return int(row['id']) if row and 'id' in row else -1
                    except Exception:
                        return -1
        except Exception:
            # Fall through to fallback
            pass
    # Fallback: append to JSONL
    p = os.path.join('data', 'factor_weight_candidates.jsonl')
    os.makedirs(os.path.dirname(p), exist_ok=True)
    try:
        async with await asyncio.to_thread(open, p, 'a', encoding='utf-8') as fh:  # type: ignore
            await asyncio.to_thread(fh.write, json.dumps(candidate, default=str) + "\n")
        return -1
    except Exception:
        try:
            with open(p, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(candidate, default=str) + "\n")
            return -1
        except Exception:
            return -1


async def persist_audit_async(action: str, payload: Any, actor: str = 'system'):
    rec = {'action': action, 'payload': payload, 'actor': actor}
    if DB_AVAILABLE and hasattr(database_adapter.db_manager, 'adapter') and database_adapter.db_manager.adapter:
        adapter = database_adapter.db_manager.adapter
        try:
            if hasattr(adapter, 'pool') and adapter.pool:
                async with adapter.pool.acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO factor_weight_audit (action, payload, actor, ts)
                        VALUES ($1, $2, $3, NOW())
                        """,
                        action, json.dumps(payload, default=str), actor
                    )
                return True
        except Exception:
            pass
    # fallback
    p = os.path.join('data', 'factor_weight_audit.jsonl')
    os.makedirs(os.path.dirname(p), exist_ok=True)
    try:
        async with await asyncio.to_thread(open, p, 'a', encoding='utf-8') as fh:  # type: ignore
            await asyncio.to_thread(fh.write, json.dumps(rec, default=str) + "\n")
        return True
    except Exception:
        try:
            with open(p, 'a', encoding='utf-8') as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
            return True
        except Exception:
            return False


# Synchronous wrappers for callers that don't want to await
def persist_candidate(candidate: Dict[str, Any]):
    try:
        loop = asyncio.get_event_loop()
    except Exception:
        loop = None
    if loop and loop.is_running():
        # schedule in background and return None (unknown id)
        asyncio.create_task(persist_candidate_async(candidate))
        return None
    try:
        return asyncio.run(persist_candidate_async(candidate))
    except Exception:
        try:
            return asyncio.get_event_loop().run_until_complete(persist_candidate_async(candidate))
        except Exception:
            return None


def persist_audit(action: str, payload: Any, actor: str = 'system'):
    try:
        loop = asyncio.get_event_loop()
    except Exception:
        loop = None
    if loop and loop.is_running():
        asyncio.create_task(persist_audit_async(action, payload, actor))
        return True
    try:
        return asyncio.run(persist_audit_async(action, payload, actor))
    except Exception:
        try:
            return asyncio.get_event_loop().run_until_complete(persist_audit_async(action, payload, actor))
        except Exception:
            return False
