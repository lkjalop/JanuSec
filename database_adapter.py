#!/usr/bin/env python3
"""
Pluggable Database Adapter - Toyota Camry Approach
Simple, reliable, easily replaceable database layer

Supports:
- Neon PostgreSQL (cloud)
- Local PostgreSQL
- SQLite (development)
- Any PostgreSQL-compatible database
"""

import os
import asyncio
import logging
logger = logging.getLogger(__name__)
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod
import json
from datetime import datetime
from src.db.migrations import apply_migrations_postgres, apply_migrations_sqlite  # type: ignore

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False
    logger.info("asyncpg not installed, database features limited")

try:
    import aiosqlite
    SQLITE_AVAILABLE = True
except ImportError:
    # Provide a lightweight async shim around the stdlib sqlite3 when aiosqlite
    # is not available. This avoids forcing tests to install aiosqlite while
    # preserving the async API surface used by the codebase.
    SQLITE_AVAILABLE = True
    import sqlite3

    class _CursorWrapper:
        def __init__(self, cursor):
            self._cursor = cursor

        async def fetchall(self):
            return await asyncio.to_thread(self._cursor.fetchall)

        async def fetchone(self):
            return await asyncio.to_thread(self._cursor.fetchone)

        # Provide a close in case callers expect it
        async def close(self):
            return await asyncio.to_thread(getattr(self._cursor, 'close', lambda: None))

    class _ConnectionWrapper:
        def __init__(self, conn):
            self._conn = conn

        async def execute(self, sql, params=None):
            def _run():
                if params is None:
                    return self._conn.execute(sql)
                return self._conn.execute(sql, params)
            cur = await asyncio.to_thread(_run)
            return _CursorWrapper(cur)

        async def commit(self):
            return await asyncio.to_thread(self._conn.commit)

        async def close(self):
            return await asyncio.to_thread(self._conn.close)

        # Compatibility: allow `row_factory` attribute access
        @property
        def row_factory(self):
            return getattr(self._conn, 'row_factory', None)

        @row_factory.setter
        def row_factory(self, val):
            setattr(self._conn, 'row_factory', val)

    class _AioSqliteShim:
        @staticmethod
        async def connect(db_path):
            # Use check_same_thread=False to allow usage from different threads
            conn = await asyncio.to_thread(sqlite3.connect, db_path, check_same_thread=False)
            return _ConnectionWrapper(conn)

    # Expose the shim under the aiosqlite name so the rest of the module
    # can operate unchanged.
    aiosqlite = _AioSqliteShim  # type: ignore

logger = logging.getLogger(__name__)

class DatabaseAdapter(ABC):
    """Abstract database adapter - Toyota Camry reliability"""

    @abstractmethod
    async def connect(self):
        """Connect to database"""
        pass

    @abstractmethod
    async def disconnect(self):
        """Disconnect from database"""
        pass

    @abstractmethod
    async def store_event(self, event_id: str, event_data: Dict[str, Any], verdict: str, confidence: float):
        """Store processed event"""
        pass

    @abstractmethod
    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events"""
        pass

    @abstractmethod
    async def store_alert(self, alert_data: Dict[str, Any]):
        """Store security alert"""
        pass

    @abstractmethod
    async def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        pass

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Database health check"""
        pass

    # ---- Optional Threat Intel IoC persistence API (no-op by default) ----
    async def intel_upsert_iocs(self, rows: List[Dict[str, Any]]):  # pragma: no cover
        """Upsert IoCs: rows of {type, value, expiry_ts, source}."""
        return

    async def intel_load_iocs(self) -> List[Dict[str, Any]]:  # pragma: no cover
        """Load non-expired IoCs; default empty list when unsupported."""
        return []

    async def intel_purge_expired(self):  # pragma: no cover
        """Purge expired IoCs; default no-op when unsupported."""
        return

class NeonPostgreSQLAdapter(DatabaseAdapter):
    """Neon PostgreSQL cloud adapter - production ready"""

    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.pool = None
        self.connected = False

    async def connect(self):
        """Connect to Neon PostgreSQL"""
        if not ASYNCPG_AVAILABLE:
            raise RuntimeError("asyncpg required for PostgreSQL")

        try:
            self.pool = await asyncpg.create_pool(
                self.connection_string,
                min_size=1,
                max_size=10,
                command_timeout=5
            )

            # Test connection and create tables
            async with self.pool.acquire() as conn:
                await self._create_tables(conn)

            # Apply migrations after creating base tables (so migrations can assume table exists or extend)
            try:
                await apply_migrations_postgres(self.pool)
            except Exception as mig_err:  # pragma: no cover
                logger.warning(f"Migration application failed: {mig_err}")
            self.connected = True
            logger.info("Connected to Neon PostgreSQL")

        except Exception as e:
            logger.error(f"Failed to connect to Neon PostgreSQL: {e}")
            raise

    async def _create_tables(self, conn):
        """Create required tables"""
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT NOW(),
                event_data JSONB,
                verdict TEXT,
                confidence FLOAT,
                processing_time_ms FLOAT,
                tenant_id TEXT DEFAULT 'default'
            )
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT NOW(),
                event_id TEXT,
                alert_type TEXT,
                severity TEXT,
                message TEXT,
                alert_data JSONB,
                tenant_id TEXT DEFAULT 'default'
            )
        """)

        # New: explicit decisions and audit_log tables (lightweight, append-only)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                event_id TEXT,
                timestamp TIMESTAMP DEFAULT NOW(),
                verdict TEXT,
                confidence FLOAT,
                reasons JSONB,
                tenant_id TEXT DEFAULT 'default'
            )
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT NOW(),
                event_id TEXT,
                action TEXT,
                actor TEXT,
                details JSONB,
                tenant_id TEXT DEFAULT 'default'
            )
        """)

        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_decisions_tenant ON decisions(tenant_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
        """)

        # API keys table for scoping & rotation
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                api_key TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                scopes TEXT,
                created_at TIMESTAMP DEFAULT NOW(),
                last_used_at TIMESTAMP,
                enabled BOOLEAN DEFAULT TRUE
            )
        """)

        # Provenance tables for human assessments and provenance entries
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS provenance_entries (
                fingerprint TEXT PRIMARY KEY,
                row JSONB,
                first_seen TIMESTAMP DEFAULT NOW(),
                tenant_id TEXT DEFAULT 'default'
            )
        """)

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS provenance_assessments (
                id SERIAL PRIMARY KEY,
                fingerprint TEXT REFERENCES provenance_entries(fingerprint),
                assessor TEXT,
                comment TEXT,
                tags JSONB,
                playbook_ref TEXT,
                ts TIMESTAMP DEFAULT NOW(),
                tenant_id TEXT DEFAULT 'default'
            )
        """)

        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_provenance_first_seen ON provenance_entries(first_seen);
            CREATE INDEX IF NOT EXISTS idx_provenance_assessments_ts ON provenance_assessments(ts);
        """)

        # Optional Row Level Security enablement (Postgres only, gated by MULTI_TENANT_RLS)
        if os.getenv('MULTI_TENANT_RLS','0').lower() in {'1','true','yes'}:
            try:  # pragma: no cover
                for tbl in ('events','alerts','decisions','audit_log'):
                    await conn.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY")
                    await conn.execute(
                        f"CREATE POLICY IF NOT EXISTS {tbl}_tenant_isolation ON {tbl} FOR ALL USING (tenant_id = current_setting('janusec.tenant_id', true))")
            except Exception as e:  # pragma: no cover
                logger.warning(f"RLS enable failed: {e}")

        # Retention configuration via environment (days)
        self.retention_events_days = float(os.getenv('RETENTION_EVENTS_DAYS', '30') or 30)
        self.retention_alerts_days = float(os.getenv('RETENTION_ALERTS_DAYS', '60') or 60)
        self.retention_decisions_days = float(os.getenv('RETENTION_DECISIONS_DAYS', '60') or 60)
        self.retention_audit_days = float(os.getenv('RETENTION_AUDIT_DAYS', '90') or 90)

        # Optional: Threat intel IoC storage (simple key-value + expiry)
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS intel_iocs (
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT,
                expiry_ts DOUBLE PRECISION,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW(),
                PRIMARY KEY (type, value)
            )
            """
        )
        await conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_intel_iocs_expiry ON intel_iocs(expiry_ts);
        """)

    async def disconnect(self):
        """Disconnect from database"""
        if self.pool:
            await self.pool.close()
        self.connected = False
        logger.info("Disconnected from Neon PostgreSQL")

    async def purge_expired(self):  # pragma: no cover
        if not self.connected:
            return
        async with self.pool.acquire() as conn:
            try:
                if self.retention_events_days > 0:
                    await conn.execute("DELETE FROM events WHERE timestamp < NOW() - INTERVAL '%s days'" % self.retention_events_days)
                if self.retention_alerts_days > 0:
                    await conn.execute("DELETE FROM alerts WHERE timestamp < NOW() - INTERVAL '%s days'" % self.retention_alerts_days)
                if self.retention_decisions_days > 0:
                    await conn.execute("DELETE FROM decisions WHERE timestamp < NOW() - INTERVAL '%s days'" % self.retention_decisions_days)
                if self.retention_audit_days > 0:
                    await conn.execute("DELETE FROM audit_log WHERE timestamp < NOW() - INTERVAL '%s days'" % self.retention_audit_days)
            except Exception as e:
                logger.warning(f"Retention purge failed: {e}")
            # Per-tenant retention overrides (integration_configs: name='retention')
            try:
                rows = await conn.fetch("SELECT tenant_id, config FROM integration_configs WHERE name='retention'")
                now = datetime.utcnow()
                import random, json as _json
                for r in rows:
                    tenant = r['tenant_id']
                    cfg = _json.loads(r['config']) if isinstance(r['config'], str) else r['config']
                    if cfg.get('legal_hold'):
                        continue
                    rd = cfg.get('retention_days')
                    sr = cfg.get('sampling_rate', 1.0)
                    if rd and rd > 0:
                        await conn.execute("DELETE FROM events WHERE tenant_id=$1 AND timestamp < NOW() - INTERVAL '%s days'" % rd, tenant)
                        await conn.execute("DELETE FROM decisions WHERE tenant_id=$1 AND timestamp < NOW() - INTERVAL '%s days'" % rd, tenant)
                    # Sampling: probabilistically drop older recent events if sampling_rate < 1
                    if sr is not None and 0 < sr < 1:
                        # Drop a limited number of events in last retention window tail to enforce sampling
                        drop_prob = 1 - sr
                        sample_rows = await conn.fetch("SELECT id FROM events WHERE tenant_id=$1 ORDER BY timestamp DESC LIMIT 500", tenant)
                        for ev in sample_rows:
                            if random.random() < drop_prob:
                                await conn.execute("DELETE FROM events WHERE id=$1", ev['id'])
            except Exception as e:  # pragma: no cover
                logger.debug(f"Per-tenant retention overrides skipped: {e}")

    # ---- Threat intel IoC helpers ----
    async def intel_upsert_iocs(self, rows: List[Dict[str, Any]]):
        if not self.connected or not rows:
            return
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                for r in rows:
                    await conn.execute(
                        """
                        INSERT INTO intel_iocs (type, value, source, expiry_ts, updated_at)
                        VALUES ($1, $2, $3, $4, NOW())
                        ON CONFLICT (type, value) DO UPDATE SET
                            source = EXCLUDED.source,
                            expiry_ts = EXCLUDED.expiry_ts,
                            updated_at = NOW()
                        """,
                        r.get('type'), r.get('value'), r.get('source'), float(r.get('expiry_ts') or 0.0)
                    )

    async def intel_load_iocs(self) -> List[Dict[str, Any]]:
        if not self.connected:
            return []
        async with self.pool.acquire() as conn:
            now = datetime.utcnow().timestamp()
            rows = await conn.fetch(
                """
                SELECT type, value, source, expiry_ts FROM intel_iocs
                WHERE expiry_ts IS NULL OR expiry_ts = 0 OR expiry_ts > $1
                """,
                now
            )
            out: List[Dict[str, Any]] = []
            for row in rows:
                out.append({
                    'type': row['type'],
                    'value': row['value'],
                    'source': row['source'],
                    'expiry_ts': float(row['expiry_ts'] or 0.0)
                })
            return out

    async def intel_purge_expired(self):
        if not self.connected:
            return
        async with self.pool.acquire() as conn:
            now = datetime.utcnow().timestamp()
            await conn.execute(
                "DELETE FROM intel_iocs WHERE expiry_ts IS NOT NULL AND expiry_ts > 0 AND expiry_ts <= $1",
                now
            )

    async def store_event(self, event_id: str, event_data: Dict[str, Any], verdict: str, confidence: float):
        """Store processed event"""
        if not self.connected:
            await self.connect()

        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO events (id, event_data, verdict, confidence, tenant_id)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (id) DO UPDATE SET
                    verdict = $3,
                    confidence = $4
                """,
                event_id,
                json.dumps(event_data),
                verdict,
                confidence,
                event_data.get('tenant_id', 'default')
            )

    async def store_provenance(self, fingerprint: str, row: Dict[str, Any], assessment: Optional[Dict[str, Any]] = None):
        """Store a provenance entry and optional human assessment."""
        if not self.connected:
            await self.connect()

        async with self.pool.acquire() as conn:
            # Upsert provenance entry
            await conn.execute(
                """
                INSERT INTO provenance_entries (fingerprint, row, tenant_id)
                VALUES ($1, $2, $3)
                ON CONFLICT (fingerprint) DO UPDATE SET row = EXCLUDED.row
                """,
                fingerprint,
                json.dumps(row),
                row.get('tenant_id', 'default')
            )
            if assessment and isinstance(assessment, dict):
                await conn.execute(
                    """
                    INSERT INTO provenance_assessments (fingerprint, assessor, comment, tags, playbook_ref, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    """,
                    fingerprint,
                    assessment.get('assessor'),
                    assessment.get('comment'),
                    json.dumps(assessment.get('tags') or []),
                    assessment.get('playbook_ref'),
                    row.get('tenant_id', 'default')
                )

    async def query_provenance(self, assessed_only: bool = False, page: int = 1, limit: int = 50):
        """Query provenance entries or assessments with pagination."""
        if not self.connected:
            return {'count': 0, 'entries': []}

        offset = max(0, (page - 1) * limit)
        async with self.pool.acquire() as conn:
            if assessed_only:
                rows = await conn.fetch(
                    """
                    SELECT pe.fingerprint, pe.row::text AS row_json, pa.assessor, pa.comment, pa.tags::text AS tags_json, pa.playbook_ref, pa.ts
                    FROM provenance_entries pe
                    JOIN provenance_assessments pa ON pe.fingerprint = pa.fingerprint
                    ORDER BY pa.ts DESC
                    LIMIT $1 OFFSET $2
                    """,
                    limit, offset
                )
                out = []
                for r in rows:
                    try:
                        out.append({
                            'fingerprint': r['fingerprint'],
                            'row': json.loads(r['row_json']) if r['row_json'] else {},
                            'assessment': {
                                'assessor': r['assessor'],
                                'comment': r['comment'],
                                'tags': json.loads(r['tags_json']) if r['tags_json'] else [],
                                'playbook_ref': r['playbook_ref'],
                                'ts': r['ts'].isoformat() if r['ts'] else None
                            }
                        })
                    except Exception:
                        continue
                return {'count': len(out), 'entries': out}
            else:
                rows = await conn.fetch(
                    """
                    SELECT fingerprint, row::text AS row_json FROM provenance_entries
                    ORDER BY first_seen DESC
                    LIMIT $1 OFFSET $2
                    """,
                    limit, offset
                )
                fingerprints = [r['fingerprint'] for r in rows]
                out = []
                if fingerprints:
                    pa_rows = await conn.fetch(
                        """
                        SELECT fingerprint, assessor, comment, tags::text AS tags_json, playbook_ref, ts
                        FROM provenance_assessments
                        WHERE fingerprint = ANY($1::text[])
                        ORDER BY ts DESC
                        """,
                        fingerprints
                    )
                    pa_map = {}
                    for pa in pa_rows:
                        pa_map.setdefault(pa['fingerprint'], []).append({
                            'assessor': pa['assessor'],
                            'comment': pa['comment'],
                            'tags': json.loads(pa['tags_json']) if pa['tags_json'] else [],
                            'playbook_ref': pa['playbook_ref'],
                            'ts': pa['ts'].isoformat() if pa['ts'] else None
                        })
                else:
                    pa_map = {}

                for r in rows:
                    try:
                        out.append({
                            'fingerprint': r['fingerprint'],
                            'row': json.loads(r['row_json']) if r['row_json'] else {},
                            'human_assessments': pa_map.get(r['fingerprint'], [])
                        })
                    except Exception:
                        continue
                return {'count': len(out), 'entries': out}

    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events"""
        if not self.connected:
            return []
        tenant_filter = os.getenv('ENFORCE_TENANT_SCOPE','1').lower() not in {'0','false','no'}
        tenant_id = os.getenv('FORCED_TENANT_ID')  # optional global override for tests
        async with self.pool.acquire() as conn:
            if tenant_filter and tenant_id:
                rows = await conn.fetch(
                    """SELECT id, timestamp, event_data, verdict, confidence FROM events WHERE tenant_id=$1 ORDER BY timestamp DESC LIMIT $2""",
                    tenant_id, limit
                )
            else:
                rows = await conn.fetch(
                    """SELECT id, timestamp, event_data, verdict, confidence FROM events ORDER BY timestamp DESC LIMIT $1""",
                    limit
                )

        return [
            {
                "id": row["id"],
                "timestamp": row["timestamp"].isoformat(),
                "event_data": json.loads(row["event_data"]),
                "verdict": row["verdict"],
                "confidence": row["confidence"]
            }
            for row in rows
        ]

    async def store_alert(self, alert_data: Dict[str, Any]):
        """Store security alert"""
        if not self.connected:
            await self.connect()

        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO alerts (event_id, alert_type, severity, message, alert_data, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                alert_data.get('event_id'),
                alert_data.get('alert_type', 'threat_detected'),
                alert_data.get('severity', 'medium'),
                alert_data.get('message', ''),
                json.dumps(alert_data),
                alert_data.get('tenant_id', 'default')
            )

    async def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        if not self.connected:
            return []
        tenant_filter = os.getenv('ENFORCE_TENANT_SCOPE','1').lower() not in {'0','false','no'}
        tenant_id = os.getenv('FORCED_TENANT_ID')
        async with self.pool.acquire() as conn:
            if tenant_filter and tenant_id:
                rows = await conn.fetch(
                    """SELECT id, timestamp, event_id, alert_type, severity, message, alert_data FROM alerts WHERE tenant_id=$1 ORDER BY timestamp DESC LIMIT $2""",
                    tenant_id, limit
                )
            else:
                rows = await conn.fetch(
                    """SELECT id, timestamp, event_id, alert_type, severity, message, alert_data FROM alerts ORDER BY timestamp DESC LIMIT $1""",
                    limit
                )

        return [
            {
                "id": row["id"],
                "timestamp": row["timestamp"].isoformat(),
                "event_id": row["event_id"],
                "alert_type": row["alert_type"],
                "severity": row["severity"],
                "message": row["message"],
                "alert_data": json.loads(row["alert_data"] or '{}')
            }
            for row in rows
        ]

    async def health_check(self) -> Dict[str, Any]:
        """Database health check"""
        try:
            if not self.connected:
                return {"status": "disconnected", "error": "Not connected"}

            async with self.pool.acquire() as conn:
                result = await conn.fetchval("SELECT 1")

                # Get table counts
                event_count = await conn.fetchval("SELECT COUNT(*) FROM events")
                alert_count = await conn.fetchval("SELECT COUNT(*) FROM alerts")

                return {
                    "status": "healthy",
                    "database": "neon_postgresql",
                    "event_count": event_count,
                    "alert_count": alert_count,
                    "pool_size": len(self.pool._holders),
                    "connection_test": result == 1
                }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "database": "neon_postgresql"
            }

class SQLiteAdapter(DatabaseAdapter):
    """SQLite adapter - development and testing"""

    def __init__(self, db_path: str = "janusec.db"):
        self.db_path = db_path
        self.connection = None
        self.connected = False

    async def connect(self):
        """Connect to SQLite"""
        if not SQLITE_AVAILABLE:
            raise RuntimeError("aiosqlite required for SQLite")

        self.connection = await aiosqlite.connect(self.db_path)
        await self._create_tables()
        try:
            await apply_migrations_sqlite(self.connection)
        except Exception as mig_err:  # pragma: no cover
            logger.warning(f"Migration application failed: {mig_err}")
        self.connected = True
        logger.info(f"Connected to SQLite: {self.db_path}")

    async def _create_tables(self):
        """Create required tables"""
        await self.connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_data TEXT,
                verdict TEXT,
                confidence REAL,
                tenant_id TEXT DEFAULT 'default'
            )
        """)

        await self.connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_id TEXT,
                alert_type TEXT,
                severity TEXT,
                message TEXT,
                alert_data TEXT,
                tenant_id TEXT DEFAULT 'default'
            )
        """)

        # New tables: decisions and audit_log (append-only for auditing & overrides)
        await self.connection.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                event_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                verdict TEXT,
                confidence REAL,
                reasons TEXT,
                tenant_id TEXT DEFAULT 'default'
            )
        """)

        await self.connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_id TEXT,
                action TEXT,
                actor TEXT,
                details TEXT,
                tenant_id TEXT DEFAULT 'default'
            )
        """)

        # Optional: Threat intel IoC storage
        await self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS intel_iocs (
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT,
                expiry_ts REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (type, value)
            )
            """
        )
        await self.connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_intel_iocs_expiry ON intel_iocs(expiry_ts)
        """)

        # API keys table (SQLite variant)
        await self.connection.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                api_key TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                scopes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                enabled INTEGER DEFAULT 1
            )
        """)

        # Retention settings (days)
        self.retention_events_days = float(os.getenv('RETENTION_EVENTS_DAYS', '30') or 30)
        self.retention_alerts_days = float(os.getenv('RETENTION_ALERTS_DAYS', '60') or 60)
        self.retention_decisions_days = float(os.getenv('RETENTION_DECISIONS_DAYS', '60') or 60)
        self.retention_audit_days = float(os.getenv('RETENTION_AUDIT_DAYS', '90') or 90)

        await self.connection.commit()

    async def disconnect(self):
        """Disconnect from SQLite"""
        if self.connection:
            await self.connection.close()
        self.connected = False
        logger.info("Disconnected from SQLite")

    async def purge_expired(self):  # pragma: no cover
        try:
            if self.retention_events_days > 0:
                await self.connection.execute("DELETE FROM events WHERE timestamp < datetime('now', ?)", (f"-{int(self.retention_events_days)} days",))
            if self.retention_alerts_days > 0:
                await self.connection.execute("DELETE FROM alerts WHERE timestamp < datetime('now', ?)", (f"-{int(self.retention_alerts_days)} days",))
            if self.retention_decisions_days > 0:
                await self.connection.execute("DELETE FROM decisions WHERE timestamp < datetime('now', ?)", (f"-{int(self.retention_decisions_days)} days",))
            if self.retention_audit_days > 0:
                await self.connection.execute("DELETE FROM audit_log WHERE timestamp < datetime('now', ?)", (f"-{int(self.retention_audit_days)} days",))
            # Per-tenant retention overrides if integration_configs exists
            try:
                cursor = await self.connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='integration_configs'")
                exists = await cursor.fetchone()
                if exists:
                    cursor = await self.connection.execute("SELECT tenant_id, config FROM integration_configs WHERE name='retention'")
                    rows = await cursor.fetchall()
                    import json as _json, random
                    for tenant_id, cfg_raw in rows:
                        cfg = _json.loads(cfg_raw or '{}')
                        if cfg.get('legal_hold'):
                            continue
                        rd = cfg.get('retention_days')
                        sr = cfg.get('sampling_rate', 1.0)
                        if rd and rd > 0:
                            await self.connection.execute("DELETE FROM events WHERE tenant_id=? AND timestamp < datetime('now', ?)",(tenant_id, f"-{int(rd)} days"))
                            await self.connection.execute("DELETE FROM decisions WHERE tenant_id=? AND timestamp < datetime('now', ?)",(tenant_id, f"-{int(rd)} days"))
                        if sr is not None and 0 < sr < 1:
                            # Sample delete of recent events to enforce sampling
                            cursor2 = await self.connection.execute("SELECT id FROM events WHERE tenant_id=? ORDER BY timestamp DESC LIMIT 500", (tenant_id,))
                            sample_rows = await cursor2.fetchall()
                            drop_prob = 1 - sr
                            for row in sample_rows:
                                if random.random() < drop_prob:
                                    await self.connection.execute("DELETE FROM events WHERE id=?", (row[0],))
            except Exception as e:
                logger.debug(f"Per-tenant retention overrides skipped: {e}")
            await self.connection.commit()
        except Exception as e:
            logger.warning(f"Retention purge failed: {e}")

    async def store_event(self, event_id: str, event_data: Dict[str, Any], verdict: str, confidence: float):
        """Store processed event"""
        await self.connection.execute(
            """
            INSERT OR REPLACE INTO events (id, event_data, verdict, confidence, tenant_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event_id, json.dumps(event_data), verdict, confidence, event_data.get('tenant_id', 'default'))
        )
        await self.connection.commit()

    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events"""
        tenant_filter = os.getenv('ENFORCE_TENANT_SCOPE','1').lower() not in {'0','false','no'}
        tenant_id = os.getenv('FORCED_TENANT_ID')

        if tenant_filter and tenant_id:
            cursor = await self.connection.execute(
                """
                SELECT id, timestamp, event_data, verdict, confidence FROM events WHERE tenant_id=? ORDER BY timestamp DESC LIMIT ?
                """,
                (tenant_id, limit)
            )
        else:
            cursor = await self.connection.execute(
                """
                SELECT id, timestamp, event_data, verdict, confidence FROM events ORDER BY timestamp DESC LIMIT ?
                """,
                (limit,)
            )
        rows = await cursor.fetchall()

        return [
            {
                "id": row[0],
                "timestamp": row[1],
                "event_data": json.loads(row[2]),
                "verdict": row[3],
                "confidence": row[4]
            }
            for row in rows
        ]

    async def store_alert(self, alert_data: Dict[str, Any]):
        """Store security alert"""
        await self.connection.execute(
            """
            INSERT INTO alerts (event_id, alert_type, severity, message, alert_data, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                alert_data.get('event_id'),
                alert_data.get('alert_type', 'threat_detected'),
                alert_data.get('severity', 'medium'),
                alert_data.get('message', ''),
                json.dumps(alert_data),
                alert_data.get('tenant_id', 'default')
            )
        )
        await self.connection.commit()

    async def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        cursor = await self.connection.execute(
            """
            SELECT id, timestamp, event_id, alert_type, severity, message, alert_data FROM alerts ORDER BY timestamp DESC LIMIT ?
            """,
            (limit,)
        )
        rows = await cursor.fetchall()

        return [
            {
                "id": row[0],
                "timestamp": row[1],
                "event_id": row[2],
                "alert_type": row[3],
                "severity": row[4],
                "message": row[5],
                "alert_data": json.loads(row[6] or '{}')
            }
            for row in rows
        ]

    async def health_check(self) -> Dict[str, Any]:
        """Database health check"""
        try:
            cursor = await self.connection.execute("SELECT COUNT(*) FROM events")
            event_count = (await cursor.fetchone())[0]

            cursor = await self.connection.execute("SELECT COUNT(*) FROM alerts")
            alert_count = (await cursor.fetchone())[0]

            # Optional counts (ignore errors if new tables absent for any reason)
            try:
                cursor = await self.connection.execute("SELECT COUNT(*) FROM decisions")
                decision_count = (await cursor.fetchone())[0]
            except Exception:
                decision_count = None
            try:
                cursor = await self.connection.execute("SELECT COUNT(*) FROM audit_log")
                audit_count = (await cursor.fetchone())[0]
            except Exception:
                audit_count = None

            return {
                "status": "healthy",
                "database": "sqlite",
                "db_path": self.db_path,
                "event_count": event_count,
                "alert_count": alert_count,
                "decision_count": decision_count,
                "audit_count": audit_count
            }

        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "database": "sqlite"
            }

class DatabaseManager:
    """Toyota Camry database manager - simple, reliable, easily replaceable"""

    def __init__(self):
        self.adapter: Optional[DatabaseAdapter] = None
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load database configuration"""
        return {
            "type": os.getenv("DB_TYPE", "sqlite").lower(),
            "neon_connection_string": os.getenv("NEON_DATABASE_URL"),
            "sqlite_path": os.getenv("SQLITE_PATH", "janusec_dev.db"),
            "auto_connect": os.getenv("DB_AUTO_CONNECT", "true").lower() == "true"
        }

    async def initialize(self):
        """Initialize database connection"""
        db_type = self.config["type"]

        try:
            if db_type == "neon" and self.config["neon_connection_string"]:
                logger.info("Initializing Neon PostgreSQL adapter")
                self.adapter = NeonPostgreSQLAdapter(self.config["neon_connection_string"])

            elif db_type == "postgresql":
                # Support for other PostgreSQL instances
                conn_str = self._build_postgres_connection_string()
                logger.info("Initializing PostgreSQL adapter")
                self.adapter = NeonPostgreSQLAdapter(conn_str)

            else:
                # Default to SQLite for development
                logger.info("Initializing SQLite adapter (development mode)")
                self.adapter = SQLiteAdapter(self.config["sqlite_path"])

            if self.config["auto_connect"]:
                await self.adapter.connect()
                logger.info(f"Database initialized: {db_type}")

        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            # Fallback to SQLite
            logger.info("Falling back to SQLite")
            self.adapter = SQLiteAdapter(self.config["sqlite_path"])
            if self.config["auto_connect"]:
                await self.adapter.connect()

    def _build_postgres_connection_string(self) -> str:
        """Build PostgreSQL connection string from environment"""
        host = os.getenv("DB_HOST", "localhost")
        port = os.getenv("DB_PORT", "5432")
        user = os.getenv("DB_USER", "postgres")
        password = os.getenv("DB_PASSWORD", "postgres")
        database = os.getenv("DB_NAME", "janusec")

        return f"postgresql://{user}:{password}@{host}:{port}/{database}"

    async def store_event(self, event_id: str, event_data: Dict[str, Any], verdict: str, confidence: float):
        """Store processed event"""
        if self.adapter:
            try:
                await self.adapter.store_event(event_id, event_data, verdict, confidence)
            except Exception as e:
                logger.error(f"Failed to store event {event_id}: {e}")

    async def get_recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent events"""
        if self.adapter:
            try:
                return await self.adapter.get_recent_events(limit)
            except Exception as e:
                logger.error(f"Failed to get recent events: {e}")
        return []

    async def store_alert(self, alert_data: Dict[str, Any]):
        """Store security alert"""
        if self.adapter:
            try:
                await self.adapter.store_alert(alert_data)
            except Exception as e:
                logger.error(f"Failed to store alert: {e}")

    async def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        if self.adapter:
            try:
                return await self.adapter.get_recent_alerts(limit)
            except Exception as e:
                logger.error(f"Failed to get recent alerts: {e}")
        return []

    async def health_check(self) -> Dict[str, Any]:
        """Database health check"""
        if self.adapter:
            return await self.adapter.health_check()
        return {"status": "not_initialized"}

    async def shutdown(self):
        """Shutdown database connection"""
        if self.adapter:
            await self.adapter.disconnect()

    async def purge_retention(self):  # pragma: no cover
        if self.adapter and hasattr(self.adapter, 'purge_expired'):
            try:
                await getattr(self.adapter, 'purge_expired')()
            except Exception as e:
                logger.warning(f"purge_retention failed: {e}")

# Global database manager instance
db_manager = DatabaseManager()

# Convenience functions for easy integration
async def init_database():
    """Initialize database - call this on startup"""
    await db_manager.initialize()

async def store_event(event_id: str, event_data: Dict[str, Any], verdict: str, confidence: float):
    """Store processed event"""
    await db_manager.store_event(event_id, event_data, verdict, confidence)

async def get_recent_events(limit: int = 100) -> List[Dict[str, Any]]:
    """Get recent events"""
    return await db_manager.get_recent_events(limit)

async def store_alert(alert_data: Dict[str, Any]):
    """Store security alert"""
    await db_manager.store_alert(alert_data)

async def get_recent_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent alerts"""
    return await db_manager.get_recent_alerts(limit)

async def database_health() -> Dict[str, Any]:
    """Database health check"""
    return await db_manager.health_check()

async def shutdown_database():
    """Shutdown database - call this on exit"""
    await db_manager.shutdown()

async def purge_retention():  # pragma: no cover
    await db_manager.purge_retention()


# ---- Dedup persistence helpers (create-on-demand, adapter-agnostic) ----
async def _ensure_dedup_tables(adapter: Optional[DatabaseAdapter]):
    if adapter is None:
        return
    try:
        if isinstance(adapter, NeonPostgreSQLAdapter):
            # create tables using asyncpg connection
            async with adapter.pool.acquire() as conn:
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS dedup_runs (
                        id TEXT PRIMARY KEY,
                        created_at TIMESTAMP DEFAULT NOW(),
                        tenant_id TEXT DEFAULT 'default',
                        params JSONB,
                        summary JSONB
                    )
                """)
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS dedup_clusters (
                        id SERIAL PRIMARY KEY,
                        run_id TEXT REFERENCES dedup_runs(id),
                        bucket INTEGER,
                        medoid JSONB,
                        members JSONB,
                        cluster_meta JSONB,
                        tenant_id TEXT DEFAULT 'default'
                    )
                """)
                await conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_dedup_runs_created_at ON dedup_runs(created_at);
                    CREATE INDEX IF NOT EXISTS idx_dedup_clusters_run_id ON dedup_clusters(run_id);
                """)
        elif isinstance(adapter, SQLiteAdapter):
            # sqlite via connection
            await adapter.connection.execute("""
                CREATE TABLE IF NOT EXISTS dedup_runs (
                    id TEXT PRIMARY KEY,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    tenant_id TEXT DEFAULT 'default',
                    params TEXT,
                    summary TEXT
                )
            """)
            await adapter.connection.execute("""
                CREATE TABLE IF NOT EXISTS dedup_clusters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    bucket INTEGER,
                    medoid TEXT,
                    members TEXT,
                    cluster_meta TEXT,
                    tenant_id TEXT DEFAULT 'default'
                )
            """)
            await adapter.connection.commit()
        else:
            # Best-effort for unknown adapters: attempt pool/connection attributes
            try:
                if hasattr(adapter, 'pool') and adapter.pool:
                    async with adapter.pool.acquire() as conn:
                        await conn.execute("""
                            CREATE TABLE IF NOT EXISTS dedup_runs (id TEXT PRIMARY KEY, created_at TIMESTAMP DEFAULT NOW(), tenant_id TEXT DEFAULT 'default', params JSONB, summary JSONB)
                        """)
                        await conn.execute("""
                            CREATE TABLE IF NOT EXISTS dedup_clusters (id SERIAL PRIMARY KEY, run_id TEXT, bucket INTEGER, medoid JSONB, members JSONB, cluster_meta JSONB, tenant_id TEXT DEFAULT 'default')
                        """)
            except Exception:
                pass
    except Exception:
        # non-fatal; table creation best-effort
        return


async def store_dedup_run(run_id: str, params: Dict[str, Any], summary: Dict[str, Any], tenant_id: str = 'default'):
    adapter = db_manager.adapter
    if adapter is None:
        return
    await _ensure_dedup_tables(adapter)
    if isinstance(adapter, NeonPostgreSQLAdapter):
        async with adapter.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO dedup_runs (id, tenant_id, params, summary)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (id) DO UPDATE SET params = EXCLUDED.params, summary = EXCLUDED.summary
                """,
                run_id, tenant_id, json.dumps(params), json.dumps(summary)
            )
    elif isinstance(adapter, SQLiteAdapter):
        await adapter.connection.execute(
            """
            INSERT OR REPLACE INTO dedup_runs (id, tenant_id, params, summary)
            VALUES (?, ?, ?, ?)
            """,
            (run_id, tenant_id, json.dumps(params), json.dumps(summary))
        )
        await adapter.connection.commit()
    else:
        # Best-effort generic fallback
        try:
            if hasattr(adapter, 'pool') and adapter.pool:
                async with adapter.pool.acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO dedup_runs (id, tenant_id, params, summary)
                        VALUES ($1, $2, $3, $4)
                        ON CONFLICT (id) DO UPDATE SET params = EXCLUDED.params, summary = EXCLUDED.summary
                        """,
                        run_id, tenant_id, json.dumps(params), json.dumps(summary)
                    )
        except Exception:
            return


async def store_dedup_cluster(run_id: str, bucket: int, medoid: Dict[str, Any], members: List[Dict[str, Any]], cluster_meta: Dict[str, Any] | None = None, tenant_id: str = 'default'):
    adapter = db_manager.adapter
    if adapter is None:
        return
    await _ensure_dedup_tables(adapter)
    if isinstance(adapter, NeonPostgreSQLAdapter):
        async with adapter.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO dedup_clusters (run_id, bucket, medoid, members, cluster_meta, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                run_id, bucket, json.dumps(medoid), json.dumps(members), json.dumps(cluster_meta or {}), tenant_id
            )
    elif isinstance(adapter, SQLiteAdapter):
        await adapter.connection.execute(
            """
            INSERT INTO dedup_clusters (run_id, bucket, medoid, members, cluster_meta, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (run_id, bucket, json.dumps(medoid), json.dumps(members), json.dumps(cluster_meta or {}), tenant_id)
        )
        await adapter.connection.commit()
    else:
        try:
            if hasattr(adapter, 'pool') and adapter.pool:
                async with adapter.pool.acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO dedup_clusters (run_id, bucket, medoid, members, cluster_meta, tenant_id)
                        VALUES ($1, $2, $3, $4, $5, $6)
                        """,
                        run_id, bucket, json.dumps(medoid), json.dumps(members), json.dumps(cluster_meta or {}), tenant_id
                    )
        except Exception:
            return


async def get_dedup_runs(limit: int = 50, offset: int = 0):
    adapter = db_manager.adapter
    if adapter is None:
        return []
    await _ensure_dedup_tables(adapter)
    out = []
    if isinstance(adapter, NeonPostgreSQLAdapter):
        async with adapter.pool.acquire() as conn:
            rows = await conn.fetch("SELECT id, created_at, tenant_id, params::text AS params_json, summary::text AS summary_json FROM dedup_runs ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
            for r in rows:
                out.append({
                    'id': r['id'],
                    'created_at': r['created_at'].isoformat() if r['created_at'] else None,
                    'tenant_id': r['tenant_id'],
                    'params': json.loads(r['params_json']) if r['params_json'] else {},
                    'summary': json.loads(r['summary_json']) if r['summary_json'] else {}
                })
        return out
    elif isinstance(adapter, SQLiteAdapter):
        cursor = await adapter.connection.execute("SELECT id, created_at, tenant_id, params, summary FROM dedup_runs ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))
        rows = await cursor.fetchall()
        for r in rows:
            out.append({
                'id': r[0],
                'created_at': r[1],
                'tenant_id': r[2],
                'params': json.loads(r[3]) if r[3] else {},
                'summary': json.loads(r[4]) if r[4] else {}
            })
        return out
    else:
        return []


async def get_dedup_clusters(run_id: str):
    adapter = db_manager.adapter
    if adapter is None:
        return []
    await _ensure_dedup_tables(adapter)
    out = []
    if isinstance(adapter, NeonPostgreSQLAdapter):
        async with adapter.pool.acquire() as conn:
            rows = await conn.fetch("SELECT bucket, medoid::text AS medoid_json, members::text AS members_json, cluster_meta::text AS meta_json FROM dedup_clusters WHERE run_id=$1 ORDER BY id", run_id)
            for r in rows:
                out.append({
                    'bucket': r['bucket'],
                    'medoid': json.loads(r['medoid_json']) if r['medoid_json'] else {},
                    'members': json.loads(r['members_json']) if r['members_json'] else [],
                    'cluster_meta': json.loads(r['meta_json']) if r['meta_json'] else {}
                })
        return out
    elif isinstance(adapter, SQLiteAdapter):
        cursor = await adapter.connection.execute("SELECT bucket, medoid, members, cluster_meta FROM dedup_clusters WHERE run_id=? ORDER BY id", (run_id,))
        rows = await cursor.fetchall()
        for r in rows:
            out.append({
                'bucket': r[0],
                'medoid': json.loads(r[1]) if r[1] else {},
                'members': json.loads(r[2]) if r[2] else [],
                'cluster_meta': json.loads(r[3]) if r[3] else {}
            })
        return out
    else:
        return []


if __name__ == "__main__":
    # Test the adapter
    async def test():
        await init_database()

        health = await database_health()
        logger.info("Database health: %s", health)

        # Test event storage
        await store_event(
            "test-123",
            {"proc_name": "test.exe", "verdict": "benign"},
            "benign",
            0.1
        )

        events = await get_recent_events(5)
        logger.info("Recent events: %s", len(events))

        await shutdown_database()

    asyncio.run(test())