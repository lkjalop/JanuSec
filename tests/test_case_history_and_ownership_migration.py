from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import duckdb
import pytest


@pytest.fixture
def history(tmp_path, monkeypatch):
    from src.repositories import case_history_repo as repo
    monkeypatch.setenv("JANUSEC_CASE_HISTORY_DB", str(tmp_path / "history.sqlite"))
    return repo


def _view():
    from src.api.ingest_endpoints import _case_view_model
    from src.api.models.case_evidence import CaseEvidenceViewModelV2
    value = _case_view_model("assessment-a", "tenant-a",
        {"status": "ready", "stage": "complete", "percent": 100},
        {"org": "tenant-a", "all_rows": [{"row_index": 0, "user": "original", "known_at": "2026-01-01T00:00:00Z"}]})
    return CaseEvidenceViewModelV2.model_validate(value).model_dump(mode="json")


def test_history_restores_recorded_state_not_current_derivation(history):
    view = _view()
    first = history.record_view("tenant-a", "assessment-a", view)
    view["breach_summary"]["what_happened"] = "A LATER CONCLUSION"
    history.record_view("tenant-a", "assessment-a", view)
    restored = history.restore_view("tenant-a", "assessment-a", "assessment-a", first["recorded_at"])
    assert "A LATER CONCLUSION" not in json.dumps(restored)
    assert restored["execution"]["historical_derivation"] == "recorded_projection"
    assert restored["report_context"]["historical_receipt"]["receipt_hash"] == first["receipt_hash"]
    assert history.restore_view("tenant-b", "assessment-a", "assessment-a", first["recorded_at"]) is None
    assert history.restore_view("tenant-a", "assessment-a", "sibling", first["recorded_at"]) is None
    assert history.restore_view("tenant-a", "assessment-a", "assessment-a", "2000-01-01T00:00:00Z") is None
    assert history.list_recorded_cases("tenant-a", "assessment-a", "2000-01-01T00:00:00Z") == []
    assert len(history.list_recorded_cases("tenant-a", "assessment-a", first["recorded_at"])) == 1


def test_history_rejects_backdating_and_owner_mismatch(history):
    view = _view()
    with pytest.raises(ValueError, match="scope_mismatch"):
        history.record_view("tenant-b", "assessment-a", view)
    view["report_context"]["as_known_at"] = "2000-01-01T00:00:00Z"
    with pytest.raises(ValueError, match="cannot_record_historical"):
        history.record_view("tenant-a", "assessment-a", view)


def test_history_sql_records_cannot_be_updated_or_deleted(history):
    history.record_view("tenant-a", "assessment-a", _view())
    conn = history._connect()
    try:
        for sql in ("DELETE FROM case_view_history", "UPDATE case_view_history SET recorded_at=0"):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                conn.execute(sql)
    finally:
        conn.close()


def test_tampered_history_is_not_silently_recomputed(history):
    receipt = history.record_view("tenant-a", "assessment-a", _view())
    conn = history._connect()
    try:
        conn.execute("DROP TRIGGER case_history_no_update")
        conn.execute("UPDATE case_view_history SET record_json=replace(record_json, 'original', 'tampered')")
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(ValueError, match="integrity_failure"):
        history.restore_view("tenant-a", "assessment-a", "assessment-a", receipt["recorded_at"])


def test_migration_uses_job_ownership_and_preserves_original(tmp_path):
    from scripts.migrate_assessment_ownership import migrate
    root = tmp_path / "misleading-tenant-b"
    root.mkdir()
    database = tmp_path / "jobs.duckdb"
    conn = duckdb.connect(str(database))
    conn.execute("CREATE TABLE assessment_jobs (id TEXT, org TEXT)")
    conn.executemany("INSERT INTO assessment_jobs VALUES (?, ?)", [("a", "tenant-a"), ("b", "tenant-a"), ("c", "unknown")])
    conn.close()
    originals = {"a": {"assessment_id": "a", "all_rows": [{"row_index": 0}]},
                 "b": {"assessment_id": "b", "org": "tenant-b"}, "c": {"assessment_id": "c"},
                 "d": {"assessment_id": "d"}}
    for aid, data in originals.items():
        (root / f"{aid}.json").write_text(json.dumps(data), encoding="utf-8")
    backup = tmp_path / "backups"
    dry = migrate(root, database, backup)
    assert dry["counts"] == {"eligible": 1, "owner_conflict": 1, "no_authoritative_owner": 2}
    assert not backup.exists()
    migrated = migrate(root, database, backup, apply=True)
    assert migrated["counts"]["migrated"] == 1
    data = json.loads((root / "a.json").read_text())
    assert data["org"] == data["tenant_id"] == "tenant-a"
    assert json.loads(next(backup.glob("*.json")).read_text()) == originals["a"]
    assert json.loads((root / "b.json").read_text()) == originals["b"]
    assert migrate(root, database, backup, apply=True)["counts"]["already_owned"] == 1


def test_migration_refuses_duplicate_snapshot_ids(tmp_path):
    from scripts.migrate_assessment_ownership import migrate
    root = tmp_path / "snapshots"
    root.mkdir()
    for name in ("one", "two"):
        (root / f"{name}.json").write_text('{"assessment_id":"a"}', encoding="utf-8")
    database = tmp_path / "jobs.duckdb"
    conn = duckdb.connect(str(database))
    conn.execute("CREATE TABLE assessment_jobs AS SELECT 'a' AS id, 'tenant-a' AS org")
    conn.close()
    assert migrate(root, database, tmp_path / "backups", apply=True)["counts"] == {"duplicate_assessment_requires_review": 2}


def test_catalog_membership_is_separate_from_mapping_review():
    from src.core.mappings.catalog_validation import validate_citation
    valid = validate_citation("nist_800_53", "AC-2")
    assert valid["canonical_id"] == "ac-2"
    assert valid["catalog_status"] == "active"
    assert valid["mapping_review"] == "unreviewed"
    assert validate_citation("nist_800_53", "AC-9999")["catalog_status"] == "invalid_id"
    assert validate_citation("iso27001", "made-up")["catalog_status"] == "catalog_not_loaded"


def test_invalid_control_ids_are_quarantined_with_provenance(monkeypatch):
    from src.core.mappings.factor_to_compliance import FACTOR_TO_COMPLIANCE
    from src.core.mappings.control_registry import factor_control_record
    monkeypatch.setitem(FACTOR_TO_COMPLIANCE, "endpoint:catalog_test", {"nist_800_53": ["AC-2", "AC-9999"]})
    record = factor_control_record("endpoint:catalog_test")
    assert record["controls"] == {"nist_800_53": ["AC-2"]}
    assert any(item["control_id"] == "AC-9999" and item["catalog_status"] == "invalid_id" for item in record["catalog_validation"])


def test_legacy_actions_bind_only_to_unique_complete_evidence_partition():
    from src.core.ingest.legacy_case_metadata import reconcile_case_metadata
    snapshot = {"assessment_id": "a", "case_partitions": [
        {"tenant_id": "t", "assessment_id": "a", "case_id": "one", "row_refs": [0], "evidence_ids": ["e0"]},
        {"tenant_id": "t", "assessment_id": "a", "case_id": "two", "row_refs": [1], "evidence_ids": ["e1"]}],
        "corrective_actions": [{"id": "safe", "row_refs": [0]},
                               {"id": "mixed", "evidence_ids": ["e0", "e1"]},
                               {"id": "unknown"}]}
    value, counts = reconcile_case_metadata(snapshot, "t")
    assert counts["bound"] == 1 and counts["ambiguous"] == 2
    assert value["corrective_actions"][0]["case_id"] == "one"
    assert all("case_id" not in item for item in value["corrective_actions"][1:])
    assert "case_id" not in snapshot["corrective_actions"][0]


@pytest.mark.asyncio
async def test_historical_ui_and_grc_export_restore_same_receipt(history, monkeypatch):
    from src.api import ingest_endpoints as ingest
    from src.api import case_intelligence_endpoints as intelligence
    from src.api.deep_analyze import persistence
    from src.core.ingest import store
    from starlette.requests import Request
    view = _view()
    receipt = history.record_view("tenant-a", "assessment-a", view)
    monkeypatch.setattr(ingest, "_assessment_tenant", lambda *_: "tenant-a")
    monkeypatch.setattr(intelligence, "_tenant", lambda *_: "tenant-a")
    monkeypatch.setattr(store, "get_job", lambda _: {"org": "tenant-a"})
    def no_current_state(*_):
        raise AssertionError("Historical reads must not consult today's snapshot")
    monkeypatch.setattr(persistence, "_get_assessment_cached", no_current_state)
    request = Request({"type": "http", "method": "GET", "headers": [], "path": "/"})
    current = await ingest.case_view("assessment-a", request, None, as_known_at=receipt["recorded_at"])
    export = await intelligence.grc_action_pack("assessment-a", request, None, format="json", as_known_at=receipt["recorded_at"])
    assert json.loads(current.body) == json.loads(export.body)
    assert json.loads(current.body)["report_context"]["historical_receipt"]["receipt_hash"] == receipt["receipt_hash"]
