"""Historical incidents repository for recurrence analysis."""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


class HistoricalIncidentsRepo:
    """Simple SQLite-backed repository for incident lookups."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        base = db_path or os.getenv("HISTORICAL_DB_PATH") or "janusec_dev.db"
        self.db_path = base
        self._init_schema()

    def _init_schema(self) -> None:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS historical_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT,
                process_name TEXT,
                host TEXT,
                user_account TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                domain TEXT,
                mitre_tags TEXT,
                factors TEXT,
                dread_score REAL,
                correlation_score REAL,
                verdict TEXT,
                outcome TEXT,
                analyst_notes TEXT,
                escalated INTEGER DEFAULT 0,
                incident_id TEXT,
                first_seen_at DATETIME,
                last_seen_at DATETIME,
                occurrence_count INTEGER DEFAULT 1,
                org TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_sha256 ON historical_incidents(sha256)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_process ON historical_incidents(process_name)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_host ON historical_incidents(host)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_ip ON historical_incidents(src_ip, dst_ip)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_outcome ON historical_incidents(outcome)"
        )
        conn.commit()
        conn.close()

    def save_incident(
        self,
        row: Dict[str, Any],
        outcome: str = "unknown",
        analyst_notes: str | None = None,
        org: str | None = None,
    ) -> int:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        sha256 = row.get("hash_sha256") or row.get("sha256") or ""
        process_name = row.get("process_name") or row.get("process") or ""
        host = row.get("host") or ""
        cur.execute(
            """
            SELECT id, occurrence_count FROM historical_incidents
            WHERE (sha256 = ? AND sha256 != '')
               OR (process_name = ? AND host = ?)
            ORDER BY updated_at DESC LIMIT 1
            """,
            (sha256, process_name, host),
        )
        existing = cur.fetchone()
        now = datetime.utcnow()
        mitre_tags = json.dumps(row.get("mitre_tags") or [])
        factors = json.dumps(row.get("factors") or [])
        dread_score = float(
            (row.get("_dread") or row.get("dread") or {}).get("score", 0.0)
            if isinstance(row.get("_dread") or row.get("dread"), dict)
            else row.get("_dread")
            or row.get("dread")
            or 0.0
        )
        corr = row.get("_correlation") or row.get("correlation") or {}
        correlation_score = float(
            corr.get("score") if isinstance(corr, dict) else corr or 0.0
        )
        if existing:
            incident_id, count = existing
            cur.execute(
                """
                UPDATE historical_incidents
                SET last_seen_at = ?, occurrence_count = ?, outcome = ?, analyst_notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    now.isoformat(),
                    int(count or 0) + 1,
                    outcome,
                    analyst_notes or "",
                    now.isoformat(),
                    incident_id,
                ),
            )
            conn.commit()
            conn.close()
            return int(incident_id)

        cur.execute(
            """
            INSERT INTO historical_incidents (
                sha256, process_name, host, user_account,
                src_ip, dst_ip, domain, mitre_tags, factors,
                dread_score, correlation_score, verdict, outcome,
                analyst_notes, escalated, incident_id,
                first_seen_at, last_seen_at, org, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sha256,
                process_name,
                host,
                row.get("user") or "",
                row.get("src_ip") or "",
                row.get("dst_ip") or "",
                row.get("domain") or "",
                mitre_tags,
                factors,
                dread_score,
                correlation_score,
                row.get("verdict") or "",
                outcome,
                analyst_notes or "",
                1 if row.get("verdict") in ("CRITICAL", "HIGH") else 0,
                row.get("incident_id") or "",
                now.isoformat(),
                now.isoformat(),
                org or "default",
                now.isoformat(),
            ),
        )
        incident_id = cur.lastrowid
        conn.commit()
        conn.close()
        return int(incident_id)

    def query_similar_incidents(
        self,
        row: Dict[str, Any],
        lookback_days: int = 90,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        sha256 = row.get("hash_sha256") or row.get("sha256") or ""
        process_name = row.get("process_name") or ""
        host = row.get("host") or ""
        src_ip = row.get("src_ip") or ""
        dst_ip = row.get("dst_ip") or ""
        mitre_tags = set(row.get("mitre_tags") or [])
        cutoff = (datetime.utcnow() - timedelta(days=lookback_days)).isoformat()
        results: List[Dict[str, Any]] = []

        if sha256:
            cur.execute(
                """
                SELECT *, 1.0 as similarity_score, 'sha256_match' as match_type
                FROM historical_incidents
                WHERE sha256 = ? AND first_seen_at >= ?
                ORDER BY last_seen_at DESC LIMIT ?
                """,
                (sha256, cutoff, limit),
            )
            rows = [dict(r) for r in cur.fetchall()]
            if rows:
                conn.close()
                return rows

        if process_name and host:
            cur.execute(
                """
                SELECT *, 0.8 as similarity_score, 'process_host_match' as match_type
                FROM historical_incidents
                WHERE process_name = ? AND host = ? AND first_seen_at >= ?
                ORDER BY last_seen_at DESC LIMIT ?
                """,
                (process_name, host, cutoff, limit),
            )
            rows = [dict(r) for r in cur.fetchall()]
            if rows:
                conn.close()
                return rows

        if mitre_tags:
            cur.execute(
                """
                SELECT *, 0.6 as similarity_score, 'mitre_overlap' as match_type
                FROM historical_incidents
                WHERE first_seen_at >= ?
                ORDER BY last_seen_at DESC LIMIT ?
                """,
                (cutoff, limit * 2),
            )
            for candidate in cur.fetchall():
                cand = dict(candidate)
                overlap = mitre_tags.intersection(
                    set(json.loads(cand.get("mitre_tags") or "[]"))
                )
                if len(overlap) >= 2:
                    cand["similarity_score"] = 0.6 + 0.1 * len(overlap)
                    cand["mitre_overlap"] = list(overlap)
                    results.append(cand)
            if results:
                conn.close()
                return sorted(
                    results, key=lambda x: x.get("similarity_score", 0), reverse=True
                )[:limit]

        ip = src_ip or dst_ip
        if ip:
            cur.execute(
                """
                SELECT *, 0.5 as similarity_score, 'ip_match' as match_type
                FROM historical_incidents
                WHERE (src_ip = ? OR dst_ip = ?) AND first_seen_at >= ?
                ORDER BY last_seen_at DESC LIMIT ?
                """,
                (ip, ip, cutoff, limit),
            )
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()
            return rows

        conn.close()
        return []


HISTORICAL_REPO = HistoricalIncidentsRepo()

__all__ = ["HistoricalIncidentsRepo", "HISTORICAL_REPO"]
