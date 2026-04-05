from __future__ import annotations

import os
import json
import time
import secrets
from typing import Optional

DB_ENABLED = os.getenv('DB_SESSIONS_ENABLED', '0').lower() in {'1','true','yes'}


def _gen_session_id() -> str:
    return secrets.token_urlsafe(32)


async def create_db_session(conn, user: dict, ttl: int = 3600) -> str:
    sid = _gen_session_id()
    expires = int(time.time()) + int(ttl)
    sql = 'INSERT INTO admin_sessions (session_id, user_info, expires_at) VALUES ($1,$2,TO_TIMESTAMP($3))'
    await conn.execute(sql, sid, json.dumps(user), expires)
    return sid


async def get_db_session(conn, sid: str) -> Optional[dict]:
    sql = 'SELECT user_info, expires_at, revoked FROM admin_sessions WHERE session_id=$1'
    row = await conn.fetchrow(sql, sid)
    if not row:
        return None
    if row.get('revoked'):
        return None
    # row['expires_at'] may be datetime; compare to now
    import datetime
    if row.get('expires_at') and row.get('expires_at') < datetime.datetime.utcnow():
        return None
    ui = row.get('user_info')
    if isinstance(ui, str):
        try:
            ui = json.loads(ui)
        except Exception:
            ui = {}
    return ui


async def revoke_db_session(conn, sid: str) -> None:
    await conn.execute('UPDATE admin_sessions SET revoked=TRUE WHERE session_id=$1', sid)
