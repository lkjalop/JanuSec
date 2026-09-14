"""A/B test persistence helpers.

This module serves two related purposes:

1. Lightweight sqlite-backed helpers for analyst-review metrics (`init_db`,
   `record`, `summary_for`) that power the `/metrics/ab_tests/*` endpoints.
2. Async database helpers for managing live AB-test metadata used by the
   streaming/decision services.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # pragma: no cover - db adapter may be unavailable in lite mode
    from db.database import execute, fetch, fetchrow
except Exception:  # pragma: no cover
    execute = fetch = fetchrow = None  # type: ignore[misc]


DB_PATH = Path("data/precision_metrics.sqlite")
_DDL = """
    CREATE TABLE IF NOT EXISTS ab_test_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ab_test_id TEXT NOT NULL,
        variant TEXT NOT NULL,
        event_id TEXT,
        label TEXT NOT NULL,
        reviewer TEXT,
        created_ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""

# In-memory fallbacks so tests without a live DB can still exercise the API.
_IN_MEMORY_TESTS: Dict[str, Dict[str, Any]] = {}
_IN_MEMORY_ASSIGNMENTS: List[Dict[str, Any]] = []


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), detect_types=sqlite3.PARSE_DECLTYPES)
    return conn


def init_db() -> None:
    with _get_conn() as conn:
        conn.execute(_DDL)


def record(
    ab_test_id: str,
    variant: str,
    label: str,
    event_id: Optional[str] = None,
    reviewer: Optional[str] = None,
) -> None:
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO ab_test_results (ab_test_id, variant, event_id, label, reviewer) VALUES (?,?,?,?,?)",
            (ab_test_id, variant, event_id, label, reviewer),
        )


def summary_for(ab_test_id: str) -> Dict[str, Dict[str, int]]:
    with _get_conn() as conn:
        cur = conn.execute(
            "SELECT variant, label, COUNT(*) as cnt FROM ab_test_results WHERE ab_test_id=? GROUP BY variant, label",
            (ab_test_id,),
        )
        rows = cur.fetchall()
    out: Dict[str, Dict[str, int]] = {}
    for variant, label, cnt in rows:
        out.setdefault(variant, {})[label] = cnt
    return out


# --- Postgres/async helpers -------------------------------------------------

CREATE_TEST = """
INSERT INTO ab_tests (id, name, description, enabled, start_at, end_at)
VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT (id) DO UPDATE SET
    name=EXCLUDED.name,
    description=EXCLUDED.description,
    enabled=EXCLUDED.enabled,
    start_at=EXCLUDED.start_at,
    end_at=EXCLUDED.end_at
"""

INSERT_ASSIGN = """
INSERT INTO ab_assignments (test_id, tenant_id, subject_id, variant)
VALUES ($1,$2,$3,$4)
"""

GET_TEST = "SELECT * FROM ab_tests WHERE id=$1"
LIST_ACTIVE = "SELECT * FROM ab_tests WHERE enabled=TRUE"
LIST_ALL = "SELECT * FROM ab_tests ORDER BY created_at DESC"
SET_ENABLED = "UPDATE ab_tests SET enabled=$1 WHERE id=$2"


async def upsert_test(
    test_id: str,
    name: Optional[str],
    description: Optional[str],
    enabled: bool,
    start_at: Optional[str],
    end_at: Optional[str],
) -> None:
    if execute is None:
        _IN_MEMORY_TESTS[test_id] = {
            "id": test_id,
            "name": name,
            "description": description,
            "enabled": enabled,
            "start_at": start_at,
            "end_at": end_at,
        }
        return
    await execute(CREATE_TEST, test_id, name, description, enabled, start_at, end_at)


async def assign_variant(test_id: str, tenant_id: Optional[str], subject_id: str, variant: str) -> None:
    if execute is None:
        _IN_MEMORY_ASSIGNMENTS.append(
            {
                "test_id": test_id,
                "tenant_id": tenant_id,
                "subject_id": subject_id,
                "variant": variant,
            }
        )
        return
    await execute(INSERT_ASSIGN, test_id, tenant_id, subject_id, variant)


async def get_test(test_id: str) -> Optional[Dict[str, Any]]:
    if fetchrow is None:
        return _IN_MEMORY_TESTS.get(test_id)
    row = await fetchrow(GET_TEST, test_id)
    return dict(row) if row else None


async def list_active() -> List[Dict[str, Any]]:
    if fetch is None:
        return [v for v in _IN_MEMORY_TESTS.values() if v.get("enabled")]
    rows = await fetch(LIST_ACTIVE)
    return [dict(r) for r in rows]


async def list_all() -> List[Dict[str, Any]]:
    if fetch is None:
        return list(_IN_MEMORY_TESTS.values())
    rows = await fetch(LIST_ALL)
    return [dict(r) for r in rows]


async def set_enabled(test_id: str, enabled: bool) -> None:
    if execute is None:
        if test_id in _IN_MEMORY_TESTS:
            _IN_MEMORY_TESTS[test_id]["enabled"] = enabled
        return
    await execute(SET_ENABLED, enabled, test_id)
