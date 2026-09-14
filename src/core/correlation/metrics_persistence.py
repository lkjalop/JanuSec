import os
import json
import asyncio
from typing import Dict


def _get_dsn():
    return os.getenv('APP_DB_DSN')


async def _write_to_db_async(rule: str, kind: str):
    dsn = _get_dsn()
    if not dsn:
        return False
    try:
        import asyncpg
        conn = await asyncpg.connect(dsn)
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS rule_feedback (
                id serial primary key,
                rule_name text,
                kind text,
                ts timestamptz default now()
            )
        ''')
        await conn.execute('INSERT INTO rule_feedback (rule_name, kind) VALUES ($1, $2)', rule, kind)
        await conn.close()
        return True
    except Exception:
        return False


def persist_metric(rule: str, kind: str):
    """Best-effort: try async DB write (fire-and-forget), otherwise append to local file."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # schedule background task
        try:
            asyncio.ensure_future(_write_to_db_async(rule, kind))
            return
        except Exception:
            pass
    try:
        # try sync run
        import asyncio as _asyncio
        _asyncio.get_event_loop().run_until_complete(_write_to_db_async(rule, kind))
        return
    except Exception:
        pass
    # fallback: append to file
    try:
        p = os.path.join('data', 'rule_feedback.log')
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'rule': rule, 'kind': kind}) + '\n')
    except Exception:
        pass
