"""Async Database Connection Handling

Provides a singleton-style asyncpg connection pool.
Falls back gracefully if asyncpg not installed yet (no-op stub) so the rest
of the system can run in reduced mode.
"""
from __future__ import annotations
import asyncio
import logging
import os
import random
from typing import Optional, Any, Callable

try:
    import asyncpg  # type: ignore
except Exception:  # pragma: no cover - dependency may be optional initially
    asyncpg = None  # type: ignore

_logger = logging.getLogger(__name__)

# Use loose Optional[Any] to avoid static analysis issues if asyncpg missing
from typing import Any as _Any
_pool: Optional[_Any] = None
_pool_lock = asyncio.Lock()

DEFAULT_DB_DSN_ENV = "APP_DB_DSN"
DEFAULT_MIN_CONN = 1
DEFAULT_MAX_CONN = 10

class DatabaseNotAvailable(RuntimeError):
    pass

async def init_pool(dsn: Optional[str] = None,
                    min_size: int = DEFAULT_MIN_CONN,
                    max_size: int = DEFAULT_MAX_CONN,
                    **connect_kwargs: Any) -> None:
    """Initialize the global connection pool.

    dsn precedence:
    1. explicit dsn param
    2. env var APP_DB_DSN
    3. individual env vars: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
    """
    global _pool
    if _pool is not None:
        return
    async with _pool_lock:
        if _pool is not None:
            return
        if asyncpg is None:
            _logger.warning("asyncpg not installed; database features disabled")
            return
        if dsn is None:
            dsn = os.getenv(DEFAULT_DB_DSN_ENV)
        if dsn is None:
            host = os.getenv("DB_HOST", "localhost")
            port = os.getenv("DB_PORT", "5432")
            user = os.getenv("DB_USER", "postgres")
            password = os.getenv("DB_PASSWORD", "postgres")
            database = os.getenv("DB_NAME", "threatsifter")
            dsn = f"postgresql://{user}:{password}@{host}:{port}/{database}"
        _logger.info(f"Initializing asyncpg pool to {dsn} ...")
        try:
            _pool = await asyncpg.create_pool(dsn=dsn, min_size=min_size, max_size=max_size, **connect_kwargs)
            _logger.info("Database pool initialized")
        except Exception as e:  # pragma: no cover
            _logger.error(f"Failed to initialize DB pool: {e}")
            raise

async def get_pool():
    if _pool is None:
        raise DatabaseNotAvailable("Database pool not initialized or asyncpg missing")
    return _pool

async def fetchrow(query: str, *args):
    if _pool is None:
        raise DatabaseNotAvailable("Database pool not initialized")
    async with _pool.acquire() as conn:
        return await conn.fetchrow(query, *args)

async def fetch(query: str, *args):
    if _pool is None:
        raise DatabaseNotAvailable("Database pool not initialized")
    async with _pool.acquire() as conn:
        return await conn.fetch(query, *args)

async def execute(query: str, *args):
    if _pool is None:
        raise DatabaseNotAvailable("Database pool not initialized")
    async with _pool.acquire() as conn:
        return await conn.execute(query, *args)

async def executemany(query: str, args_iter):
    if _pool is None:
        raise DatabaseNotAvailable("Database pool not initialized")
    async with _pool.acquire() as conn:
        async with conn.transaction():
            for args in args_iter:
                await conn.execute(query, *args)

async def with_retry(coro_factory: Callable[[], Any], *, attempts: int = 5, base_delay: float = 0.05, max_delay: float = 1.0, jitter: float = 0.1):
    """Execute an async DB operation with exponential backoff.

    coro_factory: zero-arg function returning awaitable (e.g., lambda: execute(q,*a))
    attempts: max attempts including first
    base_delay: initial backoff
    jitter: added random jitter fraction
    """
    for attempt in range(1, attempts + 1):
        try:
            return await coro_factory()
        except Exception as e:  # pragma: no cover - timing sensitive
            if attempt == attempts:
                _logger.warning(f"DB operation failed after {attempts} attempts: {e}")
                raise
            sleep_for = min(max_delay, base_delay * (2 ** (attempt - 1)))
            # add jitter
            sleep_for *= (1 + random.uniform(0, jitter))
            await asyncio.sleep(sleep_for)

async def close_pool():
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        _logger.info("Database pool closed")
