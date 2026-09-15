"""Immutable materialized case views; recording time is never backdated.

Historical reads restore an actual recorded projection, including its review
state, rather than running today's derivation against yesterday's evidence.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3

from src.core.event_time import event_epoch
from src.core.evidence_contract.records import canonical_hash

DERIVATION_VERSION = "janusec.case-view-history/v1"


def _connect():
    path = Path(os.environ.get("JANUSEC_CASE_HISTORY_DB") or
                str(Path(os.environ.get("SESSION_PERSIST_DIR", "data/assessments")) / "case_history.sqlite"))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    conn.execute("""CREATE TABLE IF NOT EXISTS case_view_history (
        tenant_id TEXT NOT NULL, assessment_id TEXT NOT NULL, case_id TEXT NOT NULL,
        recorded_at REAL NOT NULL, receipt_hash TEXT PRIMARY KEY, record_json TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS case_history_scope ON case_view_history (tenant_id, assessment_id, case_id, recorded_at)")
    for operation in ("UPDATE", "DELETE"):
        conn.execute(f"CREATE TRIGGER IF NOT EXISTS case_history_no_{operation.lower()} BEFORE {operation} ON case_view_history BEGIN SELECT RAISE(ABORT, 'immutable_case_history'); END")
    return conn


def record_view(tenant_id: str, assessment_id: str, view: dict) -> dict:
    case = view.get("case") or {}
    if not tenant_id or not assessment_id or case.get("tenant_id") != tenant_id or not case.get("id"):
        raise ValueError("case_history_scope_mismatch")
    if (view.get("report_context") or {}).get("as_known_at"):
        raise ValueError("cannot_record_historical_view_as_current")
    payload = deepcopy(view)
    now = datetime.now(timezone.utc)
    rows = (payload.get("evidence") or {}).get("rows") or []
    if any((event_epoch(row.get("known_at")) or 0) > now.timestamp() for row in rows):
        raise ValueError("case_history_future_knowledge_time")
    record = {
        "schema_version": DERIVATION_VERSION, "tenant_id": tenant_id,
        "assessment_id": assessment_id, "case_id": case["id"],
        "recorded_at": now.isoformat(), "input_hash": canonical_hash(rows),
        "view_hash": canonical_hash(payload), "view": payload,
    }
    record["receipt_hash"] = canonical_hash(record)
    conn = _connect()
    try:
        with conn:
            conn.execute("INSERT INTO case_view_history VALUES (?, ?, ?, ?, ?, ?)",
                         (tenant_id, assessment_id, case["id"], now.timestamp(),
                          record["receipt_hash"], json.dumps(record, ensure_ascii=False)))
    finally:
        conn.close()
    return {key: value for key, value in record.items() if key != "view"}


def restore_view(tenant_id: str, assessment_id: str, case_id: str, cutoff: str) -> dict | None:
    epoch = event_epoch(cutoff)
    if epoch is None:
        raise ValueError("invalid_as_known_at")
    conn = _connect()
    try:
        row = conn.execute("""SELECT receipt_hash, recorded_at, record_json FROM case_view_history
            WHERE tenant_id=? AND assessment_id=? AND case_id=? AND recorded_at<=?
            ORDER BY recorded_at DESC, receipt_hash DESC LIMIT 1""",
            (tenant_id, assessment_id, case_id, epoch)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    record = json.loads(row[2])
    digest = record.pop("receipt_hash")
    view = record["view"]
    if (digest != row[0] or digest != canonical_hash(record)
            or record.get("schema_version") != DERIVATION_VERSION
            or record.get("tenant_id") != tenant_id or record.get("assessment_id") != assessment_id
            or record.get("case_id") != case_id or view["case"]["tenant_id"] != tenant_id
            or view["case"]["id"] != case_id or event_epoch(record["recorded_at"]) != row[1]
            or canonical_hash(view) != record["view_hash"]
            or canonical_hash(view["evidence"]["rows"]) != record["input_hash"]):
        raise ValueError("case_history_integrity_failure")
    receipt = {key: value for key, value in record.items() if key != "view"}
    receipt["receipt_hash"] = digest
    view["report_context"].update(as_known_at=cutoff, historical_receipt=receipt)
    view["execution"]["historical_derivation"] = "recorded_projection"
    return view


def list_recorded_cases(tenant_id: str, assessment_id: str, cutoff: str) -> list[dict]:
    epoch = event_epoch(cutoff)
    if epoch is None:
        raise ValueError("invalid_as_known_at")
    conn = _connect()
    try:
        ids = [row[0] for row in conn.execute(
            "SELECT DISTINCT case_id FROM case_view_history WHERE tenant_id=? AND assessment_id=? AND recorded_at<=? ORDER BY case_id",
            (tenant_id, assessment_id, epoch))]
    finally:
        conn.close()
    result = []
    for case_id in ids:
        view = restore_view(tenant_id, assessment_id, case_id, cutoff)
        if view:
            result.append({"case_id": case_id, "title": view["breach_summary"]["headline"],
                           "verdict": view["case"].get("verdict", "ANALYSIS_INCOMPLETE"),
                           "status": "recorded", "tenant_id": tenant_id, "assessment_id": assessment_id})
    return result
