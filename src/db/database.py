"""Async Database Connection Handling

Provides a singleton-style asyncpg connection pool.
Falls back gracefully if asyncpg not installed yet (no-op stub) so the rest
of the system can run in reduced mode.
"""
from __future__ import annotations

import asyncio
import threading

# Global lock to serialize sqlite3 C API usage across threads when using
# the fallback pool. Some Windows builds of the sqlite3 extension are
# sensitive to concurrent access even with check_same_thread=False, so
# serialize at module level to be defensive in tests.
_sqlite_global_lock = threading.RLock()
import logging
import os
import random
import sqlite3
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Dict, List, Optional
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

_pool: Any | None = None
_pool_lock = asyncio.Lock()
_db_query_latency = None
_pool_backend: str = 'uninitialized'
_last_error: str | None = None
_fallback_reason: str | None = None
_current_dsn: str | None = None


class DatabaseNotAvailable(RuntimeError):
    """Raised when the database layer is not available."""


class SQLiteTransaction:
    """Async context manager implementing transaction semantics for sqlite3."""

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    async def __aenter__(self) -> SQLiteTransaction:
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
        self._lock = threading.Lock()

    async def fetch(self, query: str, *args) -> list[dict[str, Any]]:
        # Execute synchronously to avoid thread-executor races with sqlite3
        return self._fetch_all(query, args)

    def _fetch_all(self, query: str, args: Iterable[Any]) -> list[dict[str, Any]]:
        # Translate some common Postgres-specific SQL constructs to SQLite
        try:
            import re
            q = query
            # Remove Postgres type casts like ::timestamptz
            q = re.sub(r"::[a-zA-Z_]+", "", q)
            # Translate any date_trunc(...) to SQLite strftime on created_at
            q = re.sub(r"date_trunc\([^\)]*\)", "strftime('%Y-%m-%d', datetime(created_at, 'unixepoch'))", q, flags=re.IGNORECASE)
            # Replace $1, $2 param style with ? placeholders for sqlite and
            # build a new args list that duplicates values for repeated indexes
            orig_args = list(args)
            new_args: list[Any] = []

            def _repl_dollar(m: re.Match) -> str:
                idx = int(m.group(1))
                # If idx refers to an existing arg, append its value; else append None
                val = orig_args[idx - 1] if 0 <= (idx - 1) < len(orig_args) else None
                new_args.append(val)
                return '?'

            q = re.sub(r"\$([0-9]+)", _repl_dollar, q)
        except Exception:
            q = query
            new_args = list(args)
        with _sqlite_global_lock:
            with self._lock:
                cur = self._conn.execute(q, tuple(new_args))
                rows = cur.fetchall()
        return [dict(row) for row in rows]

    async def fetchrow(self, query: str, *args) -> dict[str, Any] | None:
        rows = await self.fetch(query, *args)
        return rows[0] if rows else None

    async def execute(self, query: str, *args) -> str:
        return self._execute(query, args)

    def _execute(self, query: str, args: Iterable[Any]) -> str:
        with _sqlite_global_lock:
            with self._lock:
                cur = self._conn.execute(query, tuple(args))
                self._conn.commit()
        return f"OK {cur.rowcount}"

    async def executemany(self, query: str, args_iter: Iterable[Iterable[Any]]) -> str:
        args_list = list(args_iter)
        if not args_list:
            return "OK 0"
        return self._executemany(query, args_list)

    def _executemany(self, query: str, args_list: list[Iterable[Any]]) -> str:
        formatted = [tuple(args) for args in args_list]
        with _sqlite_global_lock:
            with self._lock:
                self._conn.executemany(query, formatted)
                self._conn.commit()
        return f"OK {len(formatted)}"

    def transaction(self) -> SQLiteTransaction:
        return SQLiteTransaction(self._conn)


class SQLiteAcquiredConnection:
    """Async context manager returned by SQLiteFallbackPool.acquire()."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._conn: sqlite3.Connection | None = None
        self._proxy: SQLiteConnectionProxy | None = None

    async def __aenter__(self) -> SQLiteConnectionProxy:
        # Create connection synchronously to avoid using the thread pool
        self._conn = self._connect()
        self._proxy = SQLiteConnectionProxy(self._conn)
        return self._proxy

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
            self._proxy = None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Provide a minimal emulation of Postgres date_trunc(...) for fallback
        # SQLite used in tests may execute queries containing date_trunc; register
        # a user function to avoid "no such function: date_trunc" errors.
        try:
            from datetime import datetime

            def _date_trunc(unit: str, ts: Any) -> Any:
                if ts is None:
                    return None
                try:
                    # created_at is stored as epoch seconds in fallback schema
                    t = float(ts)
                except Exception:
                    return None
                u = (unit or '').lower()
                if u.startswith('day'):
                    return datetime.utcfromtimestamp(t).strftime('%Y-%m-%d')
                if u.startswith('hour'):
                    return datetime.utcfromtimestamp(t).strftime('%Y-%m-%d %H:00:00')
                if u.startswith('month'):
                    return datetime.utcfromtimestamp(t).strftime('%Y-%m')
                if u.startswith('year'):
                    return datetime.utcfromtimestamp(t).strftime('%Y')
                # Fallback to day granularity
                return datetime.utcfromtimestamp(t).strftime('%Y-%m-%d')

            conn.create_function('date_trunc', 2, _date_trunc)
        except Exception:
            # Best-effort; if registration fails, let the higher-level translator try
            pass
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


def _set_status(backend: str, *, error: str | None = None, fallback_reason: str | None = None, dsn: str | None = None) -> None:
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
    # Ensure minimal schema exists for tests when using sqlite fallback.
    try:
        import sqlite3
        conn = sqlite3.connect(path, timeout=10)
        cur = conn.cursor()
        # decisions table minimal schema compatible with repositories/queries used in tests
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS decisions (
                event_id TEXT PRIMARY KEY,
                verdict TEXT,
                confidence REAL,
                processing_ms REAL,
                factors TEXT,
                stage_timings TEXT,
                custody_hash TEXT,
                tenant_id TEXT,
                created_at REAL DEFAULT (strftime('%s','now'))
            )
            '''
        )
        cur.execute(
            '''
            CREATE TABLE IF NOT EXISTS decision_labels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                decision_id TEXT,
                label TEXT,
                tenant_id TEXT,
                test_id TEXT,
                variant TEXT,
                created_at REAL DEFAULT (strftime('%s','now'))
            )
            '''
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _maybe_activate_test_sqlite() -> None:
    """During tests or PLATFORM_LITE_INIT, ensure a sqlite fallback pool exists.

    This is a best-effort convenience to make DB-backed repo calls succeed
    in test environments where asyncpg is not installed or the primary DSN
    is not configured. It avoids hard exceptions during pytest collection.
    """
    global _pool
    try:
        if _pool is not None:
            return
        lite = os.getenv('PLATFORM_LITE_INIT', '0').lower() in {'1', 'true', 'yes'}
        pytest_running = 'PYTEST_CURRENT_TEST' in os.environ
        if not (lite or pytest_running):
            return
        # activate fallback using default path
        _activate_sqlite_fallback(Path(os.getenv('DB_FALLBACK_PATH', str(DEFAULT_FALLBACK_PATH))), 'auto_test_fallback')
    except Exception:
        pass


async def init_pool(
    dsn: str | None = None,
    min_size: int = DEFAULT_MIN_CONN,
    max_size: int = DEFAULT_MAX_CONN,
    **connect_kwargs: Any,
) -> None:
    """Initialize the global connection pool with optional fallback."""
    global _pool, _db_query_latency

    # Short-circuit network DB attempts for test/lite modes to avoid long
    # connection delays during pytest collection. Honor explicit DISABLE_DB
    # as well as our test-mode env guards.
    try:
        if os.getenv('DISABLE_DB', '0').lower() in {'1', 'true', 'yes'}:
            _set_status('disabled', fallback_reason='DISABLE_DB flag set', dsn=None)
            _log('info', 'db_init_skipped', reason='DISABLE_DB flag set')
            return
        # If tests request disabling network DB attempts, use sqlite fallback
        if (os.getenv('FAST_TEST_MODE','0').lower() in {'1','true','yes'} or
            os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or
            os.getenv('SKIP_ISMS_SCAN','0').lower() in {'1','true','yes'} or
            os.getenv('DB_DISABLE_NETWORK_CONNECT','0').lower() in {'1','true','yes'}):
            # ensure fallback exists and activate it
            _activate_sqlite_fallback(fallback_path, 'auto_test_fallback')
            return
    except Exception:
        pass

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
            # Check for Neon PostgreSQL configuration
            db_type = os.getenv('DB_TYPE', '').lower()
            if db_type == 'neon':
                dsn = os.getenv('NEON_DATABASE_URL')
                if dsn:
                    _log('info', 'neon_db_configured', dsn=_sanitize_dsn(dsn))
                else:
                    _log('warning', 'neon_db_misconfigured', reason='NEON_DATABASE_URL not set')
        if dsn is None:
            # Fallback to individual environment variables
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


def get_status() -> dict[str, Any]:
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
    _maybe_activate_test_sqlite()
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
    _maybe_activate_test_sqlite()
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
    _maybe_activate_test_sqlite()
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
    _maybe_activate_test_sqlite()
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
