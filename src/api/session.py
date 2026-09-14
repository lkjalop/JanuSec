from __future__ import annotations

import os
import json
import time
import hmac
import hashlib
from typing import Optional

COOKIE_NAME = os.getenv('ADMIN_SESSION_COOKIE', 'janusec_admin_session')
SECRET = os.getenv('ADMIN_SESSION_SECRET') or os.getenv('SECRET_KEY')
DB_ENABLED = os.getenv('DB_SESSIONS_ENABLED', '0').lower() in {'1','true','yes'}

if DB_ENABLED:
    # Use DB-backed sessions (async)
    from db.adapter import pool as _pool
    from .db_session import create_db_session, get_db_session, revoke_db_session

    async def create_session_cookie(user: dict, expires: int = 3600) -> str:
        # create DB session and return session id to store in cookie
        async with _pool.acquire() as conn:
            sid = await create_db_session(conn, user, ttl=expires)
            return sid

    async def verify_session_cookie(cookie: str) -> Optional[dict]:
        if not cookie:
            return None
        try:
            async with _pool.acquire() as conn:
                return await get_db_session(conn, cookie)
        except Exception:
            return None

    async def revoke_session_cookie(cookie: str) -> None:
        try:
            async with _pool.acquire() as conn:
                await revoke_db_session(conn, cookie)
        except Exception:
            pass
else:
    import hmac
    import hashlib

    def _sign(data: bytes) -> str:
        if not SECRET:
            raise RuntimeError('No ADMIN_SESSION_SECRET configured')
        return hmac.new(SECRET.encode('utf-8'), data, hashlib.sha256).hexdigest()

    def create_session_cookie(user: dict, expires: int = 3600) -> str:
        payload = {'user': user, 'iat': int(time.time()), 'exp': int(time.time()) + int(expires)}
        raw = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        sig = _sign(raw)
        # store as hex(json) + '.' + sig to avoid cookie chars
        return raw.hex() + '.' + sig

    def verify_session_cookie(cookie: str) -> Optional[dict]:
        if not cookie:
            return None
        try:
            raw_hex, sig = cookie.split('.', 1)
            raw = bytes.fromhex(raw_hex)
            expected = _sign(raw)
            if not hmac.compare_digest(expected, sig):
                return None
            payload = json.loads(raw.decode('utf-8'))
            if int(time.time()) > int(payload.get('exp', 0)):
                return None
            return payload.get('user')
        except Exception:
            return None

    def revoke_session_cookie(cookie: str) -> None:
        # Stateless tokens cannot be explicitly revoked
        return None
