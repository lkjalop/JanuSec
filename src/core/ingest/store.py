"""DuckDB-backed persistent store for async assessment ingest jobs.

Tables:
  assessment_jobs    — one row per upload job, tracks status/stage/progress
  raw_files          — file metadata per job
  normalized_rows    — parsed + normalized events, one row per event
  cluster_snapshots  — final cluster objects after clustering completes

All writes go through helpers that hold the DuckDB connection per-thread via
a module-level lock; DuckDB in-process mode is single-writer.
"""
from __future__ import annotations

import hashlib
import csv
import json
import logging
import os
import shutil
import threading
import time
import uuid
from typing import Iterator

logger = logging.getLogger(__name__)

_DB_PATH = os.getenv("JANUSEC_INGEST_DB", os.path.join("data", "ingest", "assessments.duckdb"))
_RAW_ROOT = os.getenv("JANUSEC_RAW_DIR", os.path.join("data", "raw"))

_conn = None
_lock = threading.Lock()


def _db():
    global _conn
    if _conn is None:
        try:
            import duckdb
        except ImportError as exc:
            raise RuntimeError("duckdb not installed — run: pip install duckdb>=0.10.0") from exc
        os.makedirs(os.path.dirname(os.path.abspath(_DB_PATH)), exist_ok=True)
        try:
            _conn = duckdb.connect(_DB_PATH)
        except Exception as exc:
            if not _recover_invalid_duckdb(exc):
                raise
            _conn = duckdb.connect(_DB_PATH)
        _init_schema(_conn)
    return _conn


def _recover_invalid_duckdb(exc: Exception) -> bool:
    """Quarantine an invalid DuckDB file so uploads can continue."""
    msg = str(exc).lower()
    if "not a valid duckdb database file" not in msg:
        return False
    if not os.path.exists(_DB_PATH):
        return False
    stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    quarantine = f"{_DB_PATH}.invalid.{stamp}"
    try:
        shutil.move(_DB_PATH, quarantine)
        wal_path = f"{_DB_PATH}.wal"
        if os.path.exists(wal_path):
            shutil.move(wal_path, f"{quarantine}.wal")
        logger.error(
            "Quarantined invalid DuckDB ingest store at %s; fresh store will be created at %s",
            quarantine,
            _DB_PATH,
        )
        return True
    except OSError:
        logger.exception("Failed to quarantine invalid DuckDB ingest store at %s", _DB_PATH)
        return False


def _init_schema(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS assessment_jobs (
            id           TEXT PRIMARY KEY,
            org          TEXT NOT NULL DEFAULT 'unknown',
            status       TEXT NOT NULL DEFAULT 'queued',
            stage        TEXT,
            percent      INTEGER DEFAULT 0,
            stage_label  TEXT,
            error        TEXT,
            row_count    INTEGER DEFAULT 0,
            cluster_count INTEGER DEFAULT 0,
            created_at   DOUBLE,
            updated_at   DOUBLE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_files (
            assessment_id TEXT NOT NULL,
            filename      TEXT NOT NULL,
            path          TEXT NOT NULL,
            size_bytes    BIGINT,
            sha256        TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS normalized_rows (
            assessment_id TEXT    NOT NULL,
            row_index     INTEGER NOT NULL,
            source_file   TEXT,
            source_type   TEXT,
            timestamp     TEXT,
            triage_score  DOUBLE  DEFAULT 0.3,
            user_entity   TEXT,
            src_ip        TEXT,
            hostname      TEXT,
            row_json      TEXT    NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_norm_assessment
            ON normalized_rows(assessment_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_norm_triage
            ON normalized_rows(assessment_id, triage_score DESC)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cluster_snapshots (
            assessment_id TEXT NOT NULL,
            cluster_id    TEXT NOT NULL,
            verdict       TEXT,
            confidence    DOUBLE,
            cluster_json  TEXT NOT NULL
        )
    """)


# ── Job CRUD ──────────────────────────────────────────────────────────────────

def create_job(assessment_id: str, org: str = "unknown") -> None:
    with _lock:
        _db().execute(
            """
            INSERT INTO assessment_jobs (id, org, status, stage, percent, stage_label,
                                         row_count, cluster_count, created_at, updated_at)
            VALUES (?, ?, 'queued', 'queued', 0, 'Queued', 0, 0, ?, ?)
            """,
            [assessment_id, org, time.time(), time.time()],
        )


def update_job(
    assessment_id: str,
    *,
    status: str | None = None,
    stage: str | None = None,
    percent: int | None = None,
    stage_label: str | None = None,
    error: str | None = None,
    row_count: int | None = None,
    cluster_count: int | None = None,
) -> None:
    sets = ["updated_at = ?"]
    params: list = [time.time()]
    if status is not None:
        sets.append("status = ?"); params.append(status)
    if stage is not None:
        sets.append("stage = ?"); params.append(stage)
    if percent is not None:
        sets.append("percent = ?"); params.append(percent)
    if stage_label is not None:
        sets.append("stage_label = ?"); params.append(stage_label)
    if error is not None:
        sets.append("error = ?"); params.append(error)
    if row_count is not None:
        sets.append("row_count = ?"); params.append(row_count)
    if cluster_count is not None:
        sets.append("cluster_count = ?"); params.append(cluster_count)
    params.append(assessment_id)
    with _lock:
        _db().execute(f"UPDATE assessment_jobs SET {', '.join(sets)} WHERE id = ?", params)


def get_job(assessment_id: str) -> dict | None:
    with _lock:
        rows = _db().execute(
            "SELECT id, org, status, stage, percent, stage_label, error, "
            "row_count, cluster_count, created_at, updated_at "
            "FROM assessment_jobs WHERE id = ?",
            [assessment_id],
        ).fetchall()
    if not rows:
        return None
    r = rows[0]
    return {
        "assessment_id": r[0], "org": r[1], "status": r[2],
        "stage": r[3], "percent": r[4], "stage_label": r[5],
        "error": r[6], "row_count": r[7], "cluster_count": r[8],
        "created_at": r[9], "updated_at": r[10],
    }


def list_recoverable_jobs(limit: int = 100) -> list[dict]:
    with _lock:
        rows = _db().execute(
            "SELECT id, org, status, stage, percent, stage_label, error, "
            "row_count, cluster_count, created_at, updated_at "
            "FROM assessment_jobs WHERE status IN ('queued', 'running') "
            "ORDER BY created_at ASC LIMIT ?",
            [limit],
        ).fetchall()
    return [
        {
            "assessment_id": r[0], "org": r[1], "status": r[2],
            "stage": r[3], "percent": r[4], "stage_label": r[5],
            "error": r[6], "row_count": r[7], "cluster_count": r[8],
            "created_at": r[9], "updated_at": r[10],
        }
        for r in rows
    ]


# ── File registration ─────────────────────────────────────────────────────────

def register_file(assessment_id: str, filename: str, path: str, size_bytes: int) -> str:
    sha = _sha256_file(path)
    with _lock:
        _db().execute(
            "INSERT INTO raw_files (assessment_id, filename, path, size_bytes, sha256) "
            "VALUES (?, ?, ?, ?, ?)",
            [assessment_id, filename, path, size_bytes, sha],
        )
    return sha


def raw_files_for(assessment_id: str) -> list[tuple[str, str]]:
    with _lock:
        rows = _db().execute(
            "SELECT path, filename FROM raw_files WHERE assessment_id = ? ORDER BY filename",
            [assessment_id],
        ).fetchall()
    return [(str(path), str(filename)) for path, filename in rows]


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


# ── Row persistence ───────────────────────────────────────────────────────────

def persist_row_batch(assessment_id: str, rows: list[dict]) -> None:
    """Insert a batch of normalized rows into DuckDB."""
    if not rows:
        return
    records = []
    for r in rows:
        records.append((
            assessment_id,
            int(r.get("row_index") or 0),
            str(r.get("_source") or r.get("source_file") or ""),
            str(r.get("_source_type") or r.get("source_type") or ""),
            str(r.get("timestamp") or ""),
            float(r.get("triage_score") or 0.3),
            str(r.get("user") or r.get("actor") or r.get("user_entity") or ""),
            str(r.get("src_ip") or ""),
            str(r.get("hostname") or r.get("host") or ""),
            json.dumps(r, default=str),
        ))
    with _lock:
        conn = _db()
        try:
            import pandas as pd
            df = pd.DataFrame.from_records(records, columns=[
                "assessment_id", "row_index", "source_file", "source_type",
                "timestamp", "triage_score", "user_entity", "src_ip",
                "hostname", "row_json",
            ])
            conn.register("_janusec_ingest_batch", df)
            conn.execute(
                "INSERT INTO normalized_rows "
                "SELECT assessment_id, row_index, source_file, source_type, "
                "timestamp, triage_score, user_entity, src_ip, hostname, row_json "
                "FROM _janusec_ingest_batch"
            )
            conn.unregister("_janusec_ingest_batch")
        except ImportError:
            tmp_path = os.path.join(
                os.path.dirname(os.path.abspath(_DB_PATH)),
                f"batch_{uuid.uuid4().hex}.tsv",
            )
            try:
                with open(tmp_path, "w", encoding="utf-8", newline="") as fh:
                    writer = csv.writer(fh, delimiter="\t", quoting=csv.QUOTE_MINIMAL)
                    writer.writerows(records)
                safe_path = tmp_path.replace("\\", "/").replace("'", "''")
                conn.execute(
                    "COPY normalized_rows "
                    "(assessment_id, row_index, source_file, source_type, timestamp, "
                    f"triage_score, user_entity, src_ip, hostname, row_json) FROM '{safe_path}' "
                    "(DELIMITER '\t', QUOTE '\"', ESCAPE '\"')"
                )
            except Exception:
                raise
            finally:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
        except Exception:
            try:
                conn.unregister("_janusec_ingest_batch")
            except Exception:
                pass
            raise


def count_rows(assessment_id: str) -> int:
    with _lock:
        r = _db().execute(
            "SELECT COUNT(*) FROM normalized_rows WHERE assessment_id = ?",
            [assessment_id],
        ).fetchone()
    return int(r[0]) if r else 0


def load_rows(
    assessment_id: str,
    *,
    min_triage: float = 0.0,
    limit: int | None = None,
    offset: int = 0,
    row_indices: list[int] | None = None,
) -> list[dict]:
    """Load rows from DuckDB back into Python dicts.

    Critical addition #1 (triage pre-filter): callers pass min_triage to
    exclude noise rows from the clustering stage, avoiding O(n²) blowup.
    """
    sql = (
        "SELECT row_json FROM normalized_rows "
        "WHERE assessment_id = ? AND triage_score >= ? "
    )
    params: list = [assessment_id, min_triage]
    if row_indices:
        placeholders = ", ".join(["?"] * len(row_indices))
        sql += f"AND row_index IN ({placeholders}) "
        params.extend(int(i) for i in row_indices)
    sql += "ORDER BY triage_score DESC "
    if limit:
        sql += " LIMIT ?"
        params.append(limit)
        if offset:
            sql += " OFFSET ?"
            params.append(offset)
    with _lock:
        rows_raw = _db().execute(sql, params).fetchall()
    result = []
    for (rj,) in rows_raw:
        try:
            result.append(json.loads(rj))
        except Exception:
            pass
    return result


def load_all_rows(assessment_id: str) -> list[dict]:
    """Load every row regardless of triage score (for full assessment object)."""
    return load_rows(assessment_id, min_triage=0.0)


def count_evidence_rows(
    assessment_id: str,
    *,
    min_triage: float = 0.0,
    row_indices: list[int] | None = None,
) -> int:
    sql = (
        "SELECT COUNT(*) FROM normalized_rows "
        "WHERE assessment_id = ? AND triage_score >= ? "
    )
    params: list = [assessment_id, min_triage]
    if row_indices:
        placeholders = ", ".join(["?"] * len(row_indices))
        sql += f"AND row_index IN ({placeholders}) "
        params.extend(int(i) for i in row_indices)
    with _lock:
        r = _db().execute(sql, params).fetchone()
    return int(r[0]) if r else 0


def source_counts(assessment_id: str) -> dict[str, int]:
    with _lock:
        rows = _db().execute(
            "SELECT COALESCE(source_file, ''), COUNT(*) "
            "FROM normalized_rows WHERE assessment_id = ? "
            "GROUP BY source_file ORDER BY COUNT(*) DESC",
            [assessment_id],
        ).fetchall()
    return {str(src or "unknown"): int(count) for src, count in rows}


# Critical addition #4: SQL entity-grouping query to pre-build pivot buckets.
# This groups rows by shared entity (user, IP, host) entirely in DuckDB before
# Python pair evaluation — the Python loop then only sees pre-formed groups.

def entity_pivot_groups(assessment_id: str, min_triage: float = 0.15) -> dict[str, list[int]]:
    """Return {pivot_key: [row_index, ...]} groups via DuckDB, capped per entity.

    By doing the grouping in SQL we avoid loading all rows into Python just to
    build the inverted index — DuckDB scans 44K rows in ~50ms.
    """
    with _lock:
        conn = _db()
        # User pivots
        user_rows = conn.execute(
            """
            SELECT user_entity, row_index
            FROM normalized_rows
            WHERE assessment_id = ? AND triage_score >= ?
              AND user_entity IS NOT NULL AND user_entity != ''
            ORDER BY triage_score DESC
            """,
            [assessment_id, min_triage],
        ).fetchall()
        ip_rows = conn.execute(
            """
            SELECT src_ip, row_index
            FROM normalized_rows
            WHERE assessment_id = ? AND triage_score >= ?
              AND src_ip IS NOT NULL AND src_ip != ''
            ORDER BY triage_score DESC
            """,
            [assessment_id, min_triage],
        ).fetchall()
        host_rows = conn.execute(
            """
            SELECT hostname, row_index
            FROM normalized_rows
            WHERE assessment_id = ? AND triage_score >= ?
              AND hostname IS NOT NULL AND hostname != ''
            ORDER BY triage_score DESC
            """,
            [assessment_id, min_triage],
        ).fetchall()

    pivot: dict[str, list[int]] = {}
    _CAP = 200
    for entity, row_idx in user_rows:
        k = f"user:{entity.lower()}"
        pivot.setdefault(k, [])
        if len(pivot[k]) < _CAP:
            pivot[k].append(row_idx)
    for ip, row_idx in ip_rows:
        k = f"ip:{ip}"
        pivot.setdefault(k, [])
        if len(pivot[k]) < _CAP:
            pivot[k].append(row_idx)
    for host, row_idx in host_rows:
        k = f"host:{host.lower()}"
        pivot.setdefault(k, [])
        if len(pivot[k]) < _CAP:
            pivot[k].append(row_idx)

    return {k: v for k, v in pivot.items() if len(v) >= 2}


# ── Cluster persistence ───────────────────────────────────────────────────────

def persist_clusters(assessment_id: str, clusters: list[dict]) -> None:
    if not clusters:
        return
    records = [
        (
            assessment_id,
            str(c.get("cluster_id") or ""),
            str(c.get("verdict") or c.get("final_verdict") or ""),
            float(c.get("confidence") or 0.0),
            json.dumps(c, default=str),
        )
        for c in clusters
    ]
    with _lock:
        _db().executemany(
            "INSERT INTO cluster_snapshots "
            "(assessment_id, cluster_id, verdict, confidence, cluster_json) "
            "VALUES (?, ?, ?, ?, ?)",
            records,
        )


# ── Raw file storage ──────────────────────────────────────────────────────────

def raw_dir_for(assessment_id: str) -> str:
    path = os.path.join(_RAW_ROOT, assessment_id)
    os.makedirs(path, exist_ok=True)
    return path
