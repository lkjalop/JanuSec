from __future__ import annotations
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os

DB_PATH = os.environ.get("HEARTBEAT_DB_PATH", "data/heartbeat.db")


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ingest_counts (
            tenant_id TEXT,
            source TEXT,
            bucket_ts TEXT,
            count INTEGER,
            PRIMARY KEY (tenant_id, source, bucket_ts)
        )
        """
    )
    return conn


def _bucket_hour(ts: datetime) -> str:
    # Hour bucket ISO
    b = ts.replace(minute=0, second=0, microsecond=0)
    return b.isoformat() + "Z"


def record_ingest(tenant_id: str, source: str, ts: Optional[datetime] = None, count: int = 1) -> None:
    ts = ts or datetime.utcnow()
    bucket = _bucket_hour(ts)
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO ingest_counts (tenant_id, source, bucket_ts, count) VALUES (?,?,?,?) ON CONFLICT(tenant_id,source,bucket_ts) DO UPDATE SET count=count+?",
        (tenant_id, source, bucket, count, count),
    )
    conn.commit()
    conn.close()


def get_actual_volume_last_hour(tenant_id: str, source: str) -> int:
    now = datetime.utcnow()
    last_hour = _bucket_hour(now - timedelta(hours=1))
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT count FROM ingest_counts WHERE tenant_id=? AND source=? AND bucket_ts=?",
        (tenant_id, source, last_hour),
    )
    row = cur.fetchone()
    conn.close()
    return row[0] if row else 0


def get_baseline_hourly(tenant_id: str, source: str, days: int = 7) -> float:
    # Average per-hour count over last `days` days
    since = datetime.utcnow() - timedelta(days=days)
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT avg(count) FROM ingest_counts WHERE tenant_id=? AND source=? AND bucket_ts>=?",
        (tenant_id, source, since.replace(minute=0, second=0, microsecond=0).isoformat() + "Z"),
    )
    row = cur.fetchone()
    conn.close()
    return float(row[0]) if row and row[0] is not None else 0.0


def detect_missing_sources(tenant_id: str, expected_sources: list, days_baseline: int = 7, drop_threshold: float = 0.2) -> Dict[str, Dict[str, Any]]:
    """Return anomalies per source: status: no_logs/volume_drop/ok with expected/actual/severity"""
    anomalies = {}
    for s in expected_sources:
        expected = get_baseline_hourly(tenant_id, s, days=days_baseline)
        actual = get_actual_volume_last_hour(tenant_id, s)
        if actual == 0:
            anomalies[s] = {"status": "no_logs", "expected": expected, "actual": 0, "severity": "critical"}
        elif expected > 0 and actual < expected * drop_threshold:
            anomalies[s] = {"status": "volume_drop", "expected": expected, "actual": actual, "severity": "high"}
    return anomalies
