"""DB adapter normalization helpers.

Provides unified async-friendly wrappers around common DB adapter methods and
Postgres advisory lock helpers when using asyncpg / psycopg2.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


def _get_db_module():
    try:
        from db import database as _db
        return _db
    except Exception:
        return None


async def execute(sql: str, *args):
    _db = _get_db_module()
    if not _db:
        raise RuntimeError('db.database adapter not available')
    fn = getattr(_db, 'execute', None) or getattr(_db, 'run', None) or getattr(_db, 'execute_query', None)
    if fn is None:
        raise RuntimeError('No execute-like function found on db adapter')
    if asyncio.iscoroutinefunction(fn):
        return await fn(sql, *args)
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fn, sql, *args)


async def fetch(sql: str, *args):
    _db = _get_db_module()
    if not _db:
        raise RuntimeError('db.database adapter not available')
    fn = getattr(_db, 'fetch', None) or getattr(_db, 'query', None) or getattr(_db, 'fetchall', None)
    if fn is None:
        raise RuntimeError('No fetch-like function found on db adapter')
    if asyncio.iscoroutinefunction(fn):
        return await fn(sql, *args)
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fn, sql, *args)


async def with_advisory_lock(key: int, timeout: int = 10):
    """Async context manager that attempts to acquire a Postgres advisory lock.

    If the underlying adapter isn't Postgres/doesn't expose advisory lock support,
    this becomes a no-op context manager.
    """
    class _Ctx:
        async def __aenter__(self_inner):
            _db = _get_db_module()
            if not _db:
                return None
            try:
                # Support asyncpg style: execute('SELECT pg_advisory_lock($1)', key)
                fn = getattr(_db, 'execute', None) or getattr(_db, 'run', None)
                if fn and asyncio.iscoroutinefunction(fn):
                    await fn('SELECT pg_advisory_lock($1)', key)
                else:
                    # best-effort sync call
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, getattr(_db, 'execute', lambda *a, **k: None), 'SELECT pg_advisory_lock(%s)' % key)
            except Exception:
                logger.debug('Failed to obtain advisory lock; proceeding without lock')
            return None

        async def __aexit__(self_inner, exc_type, exc, tb):
            _db = _get_db_module()
            if not _db:
                return False
            try:
                fn = getattr(_db, 'execute', None) or getattr(_db, 'run', None)
                if fn and asyncio.iscoroutinefunction(fn):
                    await fn('SELECT pg_advisory_unlock($1)', key)
                else:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, getattr(_db, 'execute', lambda *a, **k: None), 'SELECT pg_advisory_unlock(%s)' % key)
            except Exception:
                logger.debug('Failed to release advisory lock; proceeding')
            return False

    return _Ctx()
