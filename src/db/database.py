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
import sqlite3
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlsplit, urlunsplit

try:
    import asyncpg  # type: ignore
    try:
        from prometheus_client import Histogram  # type: ignore
    except Exception:  # pragma: no cover
        Histogram = None  # type: ignore
except Exception:  # pragma: no cover - dependency may be optional initially
    asyncpg = None  # type: ignore
    Histogram = None  # type: ignore

try:  # pragma: no cover - optional structured logging
    import structlog  # type: ignore
except Exception:
    structlog = None  # type: ignore

_logger = logging.getLogger(__name__)
_struct_logger = structlog.get_logger(__name__) if structlog else None

def _log(level: str, event: str, **kwargs: Any) -> None:
    """Emit log messages with optional structlog enrichment."""
    message_parts = [f"{key}={value}" for key, value in kwargs.items() if value is not None]
    base_message = event if not message_parts else f"{event}: {', '.join(message_parts)}"
    log_fn = getattr(_logger, level, _logger.info)
    log_fn(base_message)
    if _struct_logger:
        struct_fn = getattr(_struct_logger, level, _struct_logger.info)
        struct_fn(event, **{k: v for k, v in kwargs.items() if v is not None})

def _sanitize_dsn(dsn: str) -> str:
    """Mask credentials from a DSN before logging."""
    try:
        parts = urlsplit(dsn)
        if not parts.scheme:
            return dsn
        netloc = parts.netloc
        if '@' in netloc:
            user_info, host_info = netloc.rsplit('@', 1)
            if ':' in user_info:
                username, _ = user_info.split(':', 1)
                user_info = f"{username}:***"
            else:
                user_info = f"{user_info}:***"
            netloc = f"{user_info}@{host_info}"
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:  # pragma: no cover - defensive sanitization
        return dsn.split('@', 1)[-1] if '@' in dsn else dsn

DEFAULT_DB_DSN_ENV = "APP_DB_DSN"
DEFAULT_MIN_CONN = 1
DEFAULT_MAX_CONN = 10
DEFAULT_FALLBACK_PATH = Path("data/cache/fallback.sqlite")

_pool: Optional[Any] = None
_pool_lock = asyncio.Lock()
_db_query_latency = None
_pool_backend: str = 'uninitialized'
_last_error: Optional[str] = None
_fallback_reason: Optional[str] = None
_current_dsn: Optional[str] = None


class DatabaseNotAvailable(RuntimeError):
    """Raised when the database layer is not available."""


class SQLiteTransaction:
    """Async context manager implementing transaction semantics for sqlite3."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    async def __aenter__(self) -> "SQLiteTransaction":
        await asyncio.to_thread(self._conn.execute, 'BEGIN')
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if exc_type:
            await asyncio.to_thread(self._conn.rollback)
        else:
            await asyncio.to_thread(self._conn.commit)


class SQLiteConnectionProxy:
    """Small shim providing async methods compatible with asyncpg usage patterns."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    async def fetch(self, query: str, *args) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._fetch_all, query, args)

    def _fetch_all(self, query: str, args: Iterable[Any]) -> List[Dict[str, Any]]:
        cur = self._conn.execute(query, tuple(args))
        rows = cur.fetchall()
        return [dict(row) for row in rows]

    async def fetchrow(self, query: str, *args) -> Optional[Dict[str, Any]]:
        rows = await self.fetch(query, *args)
        return rows[0] if rows else None

    async def execute(self, query: str, *args) -> str:
        return await asyncio.to_thread(self._execute, query, args)

    def _execute(self, query: str, args: Iterable[Any]) -> str:
        cur = self._conn.execute(query, tuple(args))
        self._conn.commit()
        return f"OK {cur.rowcount}"

    async def executemany(self, query: str, args_iter: Iterable[Iterable[Any]]) -> str:
        args_list = list(args_iter)
        if not args_list:
            return "OK 0"
        return await asyncio.to_thread(self._executemany, query, args_list)

    def _executemany(self, query: str, args_list: List[Iterable[Any]]) -> str:
        formatted = [tuple(args) for args in args_list]
        self._conn.executemany(query, formatted)
        self._conn.commit()
        return f"OK {len(formatted)}"

    def transaction(self) -> SQLiteTransaction:
        return SQLiteTransaction(self._conn)


class SQLiteAcquiredConnection:
    """Async context manager returned by SQLiteFallbackPool.acquire()."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._conn: Optional[sqlite3.Connection] = None
        self._proxy: Optional[SQLiteConnectionProxy] = None

    async def __aenter__(self) -> SQLiteConnectionProxy:
        self._conn = await asyncio.to_thread(self._connect)
        self._proxy = SQLiteConnectionProxy(self._conn)
        return self._proxy

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._conn is not None:
            await asyncio.to_thread(self._conn.close)
            self._conn = None
            self._proxy = None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn


class SQLiteFallbackPool:
    """Minimal pool abstraction to mimic asyncpg interface using sqlite3."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def acquire(self) -> SQLiteAcquiredConnection:
        return SQLiteAcquiredConnection(self._path)

    async def close(self) -> None:
        return None

    @property
    def path(self) -> Path:
        return self._path


def _set_status(backend: str, *, error: Optional[str] = None, fallback_reason: Optional[str] = None, dsn: Optional[str] = None) -> None:
    global _pool_backend, _last_error, _fallback_reason, _current_dsn
    _pool_backend = backend
    _last_error = error
    _fallback_reason = fallback_reason
    if dsn is not None:
        _current_dsn = dsn


def _activate_sqlite_fallback(path: Path, reason: str) -> None:
    global _pool
    _pool = SQLiteFallbackPool(path)
    reason_summary = reason.split('\n', 1)[0] if reason else 'primary_connection_failed'
    fallback_path = f"sqlite:///{path}"
    _set_status('sqlite', error=reason_summary, fallback_reason='primary_db_unavailable', dsn=fallback_path)
    _log('warning', 'db_fallback_activated', backend='sqlite', path=str(path), reason=reason_summary)


async def init_pool(
    dsn: Optional[str] = None,
    min_size: int = DEFAULT_MIN_CONN,
    max_size: int = DEFAULT_MAX_CONN,
    **connect_kwargs: Any,
) -> None:
    """Initialize the global connection pool with optional fallback."""
    global _pool, _db_query_latency

    if os.getenv('DISABLE_DB', '0').lower() in {'1', 'true', 'yes'}:
        _set_status('disabled', fallback_reason='DISABLE_DB flag set', dsn=None)
        _log('info', 'db_init_skipped', reason='DISABLE_DB flag set')
        return

    if _pool is not None:
        return

    async with _pool_lock:
        if _pool is not None:
            return

        fallback_enabled = os.getenv('ENABLE_DB_FALLBACK', '1').lower() not in {'0', 'false', 'no'}
        fallback_strategy = os.getenv('DB_FALLBACK_STRATEGY', 'sqlite').lower()
        fallback_path = Path(os.getenv('DB_FALLBACK_PATH', str(DEFAULT_FALLBACK_PATH)))

        if asyncpg is None:
            _set_status('missing_dependency', error='asyncpg_not_installed', fallback_reason=None, dsn=None)
            _log('warning', 'db_asyncpg_missing')
            if fallback_enabled and fallback_strategy in {'sqlite', 'auto'}:
                _activate_sqlite_fallback(fallback_path, 'asyncpg_not_installed')
            return

        if dsn is None:
            dsn = os.getenv(DEFAULT_DB_DSN_ENV)
        if dsn is None:
            host = os.getenv('DB_HOST', 'localhost')
            port = os.getenv('DB_PORT', '5432')
            user = os.getenv('DB_USER', 'postgres')
            password = os.getenv('DB_PASSWORD', 'postgres')
            database = os.getenv('DB_NAME', 'janusec')
            dsn = f"postgresql://{user}:{password}@{host}:{port}/{database}"

        sanitized = _sanitize_dsn(dsn)
        _log('info', 'db_init_attempt', backend='asyncpg', dsn=sanitized, min_size=min_size, max_size=max_size)

        try:
            _pool = await asyncpg.create_pool(dsn=dsn, min_size=min_size, max_size=max_size, **connect_kwargs)
            if _db_query_latency is None and Histogram:
                try:
                    _db_query_latency = Histogram('db_query_latency_seconds', 'DB query latency', ['op'])  # type: ignore[arg-type]
                except Exception:  # pragma: no cover - metrics optional
                    _db_query_latency = None
            _set_status('asyncpg', error=None, fallback_reason=None, dsn=sanitized)
            _log('info', 'db_init_success', backend='asyncpg', dsn=sanitized)
        except Exception as exc:  # pragma: no cover - connection issues
            error_summary = str(exc).split('\n', 1)[0]
            _set_status('error', error=error_summary, fallback_reason=None, dsn=sanitized)
            _log('error', 'db_init_failed', backend='asyncpg', dsn=sanitized, error=error_summary)
            if fallback_enabled and fallback_strategy in {'sqlite', 'auto'}:
                _activate_sqlite_fallback(fallback_path, error_summary)
            else:
                raise


async def get_pool() -> Any:
    if _pool is None:
        raise DatabaseNotAvailable('Database pool not initialized or unavailable')
    return _pool


def is_fallback_active() -> bool:
    return _pool_backend not in {'asyncpg', 'disabled', 'uninitialized'}


def get_status() -> Dict[str, Any]:
    return {
        'backend': _pool_backend,
        'available': _pool is not None,
        'fallback_active': is_fallback_active(),
        'fallback_reason': _fallback_reason,
        'last_error': _last_error,
        'dsn': _current_dsn,
    }


async def fetchrow(query: str, *args):
    if os.getenv('DISABLE_DB', '0').lower() in {'1', 'true', 'yes'}:
        raise DatabaseNotAvailable('Database disabled by DISABLE_DB')
    if _pool is None:
        raise DatabaseNotAvailable('Database pool not initialized')
    async with _pool.acquire() as conn:  # type: ignore[union-attr]
        start = None
        loop = asyncio.get_event_loop()
        if _db_query_latency:
            start = loop.time()
        try:
            if hasattr(conn, 'fetchrow'):
                return await conn.fetchrow(query, *args)
            result = await conn.fetch(query, *args)
            result = list(result)
            return result[0] if result else None
        finally:
            if _db_query_latency and start is not None:
                try:
                    _db_query_latency.labels('fetchrow').observe(loop.time() - start)  # type: ignore[operator]
                except Exception:
                    pass


async def fetch(query: str, *args):
    if os.getenv('DISABLE_DB', '0').lower() in {'1', 'true', 'yes'}:
        raise DatabaseNotAvailable('Database disabled by DISABLE_DB')
    if _pool is None:
        raise DatabaseNotAvailable('Database pool not initialized')
    async with _pool.acquire() as conn:  # type: ignore[union-attr]
        start = None
        loop = asyncio.get_event_loop()
        if _db_query_latency:
            start = loop.time()
        try:
            return await conn.fetch(query, *args)
        finally:
            if _db_query_latency and start is not None:
                try:
                    _db_query_latency.labels('fetch').observe(loop.time() - start)  # type: ignore[operator]
                except Exception:
                    pass


async def execute(query: str, *args):
    if os.getenv('DISABLE_DB', '0').lower() in {'1', 'true', 'yes'}:
        raise DatabaseNotAvailable('Database disabled by DISABLE_DB')
    if _pool is None:
        raise DatabaseNotAvailable('Database pool not initialized')
    async with _pool.acquire() as conn:  # type: ignore[union-attr]
        start = None
        loop = asyncio.get_event_loop()
        if _db_query_latency:
            start = loop.time()
        try:
            return await conn.execute(query, *args)
        finally:
            if _db_query_latency and start is not None:
                try:
                    _db_query_latency.labels('execute').observe(loop.time() - start)  # type: ignore[operator]
                except Exception:
                    pass


async def executemany(query: str, args_iter: Iterable[Iterable[Any]]):
    if os.getenv('DISABLE_DB', '0').lower() in {'1', 'true', 'yes'}:
        raise DatabaseNotAvailable('Database disabled by DISABLE_DB')
    if _pool is None:
        raise DatabaseNotAvailable('Database pool not initialized')
    async with _pool.acquire() as conn:  # type: ignore[union-attr]
        start = None
        loop = asyncio.get_event_loop()
        if _db_query_latency:
            start = loop.time()
        try:
            if hasattr(conn, 'executemany'):
                return await conn.executemany(query, args_iter)
            async with conn.transaction():
                for args in args_iter:
                    await conn.execute(query, *args)
        finally:
            if _db_query_latency and start is not None:
                try:
                    _db_query_latency.labels('executemany').observe(loop.time() - start)  # type: ignore[operator]
                except Exception:
                    pass


async def with_retry(
    coro_factory: Callable[[], Any],
    *,
    attempts: int = 5,
    base_delay: float = 0.05,
    max_delay: float = 1.0,
    jitter: float = 0.1,
):
    """Execute an async DB operation with exponential backoff."""
    for attempt in range(1, attempts + 1):
        try:
            return await coro_factory()
        except Exception as exc:  # pragma: no cover - timing sensitive
            if attempt == attempts:
                _log('warning', 'db_operation_failed', attempts=attempts, error=str(exc))
                raise
            sleep_for = min(max_delay, base_delay * (2 ** (attempt - 1)))
            sleep_for *= (1 + random.uniform(0, jitter))
            await asyncio.sleep(sleep_for)


async def close_pool() -> None:
    global _pool, _db_query_latency
    if _pool is not None:
        close_coro = getattr(_pool, 'close', None)
        if close_coro:
            try:
                await close_coro()
            except Exception:
                pass
        _pool = None
        _db_query_latency = None
        _set_status('uninitialized', error=None, fallback_reason=None, dsn=None)
        _log('info', 'db_pool_closed')
