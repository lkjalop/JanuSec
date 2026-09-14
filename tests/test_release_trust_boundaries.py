"""Release regressions: telemetry descriptions and filenames confer no authority."""
import json

import pytest
from fastapi.testclient import TestClient

pytestmark = pytest.mark.acceptance


@pytest.mark.parametrize("title", [
    "Impossible travel ruled out. No credential dumping occurred.",
    "Training example: rclone exfiltration and LSASS credential dumping",
    "Denied request: credential dumping",
])
def test_untyped_descriptions_cannot_confirm_a_breach(title, monkeypatch):
    from src.core.ingest.threat_case_builder import build_threat_cases
    monkeypatch.setenv("JANUSEC_ALLOW_LEGACY_THREAT_CASES", "1")
    row = {"row_index": 0, "title": title, "_lane": "telemetry_evidence"}
    cases = build_threat_cases([], [row])["threat_cases"]
    assert cases
    assert all(c["verdict"] == "ANALYSIS_INCOMPLETE" for c in cases)
    assert cases[0]["row_refs"] == [0]
    assert cases[0]["confidence"] == 0


def test_unknown_factor_with_known_domain_is_unmapped():
    from src.core.mappings.factor_to_compliance import get_compliance_hits
    assert get_compliance_hits(["endpoint:totally_made_up_thing_xyz"]) == {}


@pytest.mark.parametrize("storage", ["disk", "cache"])
@pytest.mark.parametrize("owner", ["another-tenant", None])
def test_report_requires_explicit_snapshot_ownership(tmp_path, monkeypatch, storage, owner):
    from src.api.server import app
    from src.api.deep_analyze.persistence import REPORT_STORE
    from tests._helpers import default_test_headers
    aid = "ownership-negative-" + storage + str(owner)
    snapshot = {"assessment_id": aid, "rows": [{"user": "OTHER_TENANT_SENTINEL"}]}
    if owner:
        snapshot["org"] = owner
    monkeypatch.setenv("SESSION_PERSIST_DIR", str(tmp_path))
    if storage == "cache":
        monkeypatch.setitem(REPORT_STORE, aid, snapshot)
    else:
        directory = tmp_path / (owner or "default")
        directory.mkdir()
        (directory / (aid + ".json")).write_text(json.dumps(snapshot), encoding="utf-8")
    response = TestClient(app).get(
        f"/api/v1/report/ingestion?assessment_id={aid}&format=json&persist=false",
        headers={**default_test_headers(), "x-tenant-id": "default"},
    )
    assert response.status_code == 404
    assert "OTHER_TENANT_SENTINEL" not in response.text


def test_owned_report_loads_exact_snapshot_without_other_decisions(monkeypatch):
    from src.api.server import app, _record_decision
    from src.api.deep_analyze.persistence import REPORT_STORE
    from tests._helpers import default_test_headers
    aid = "owned-explicit-report"
    monkeypatch.setitem(REPORT_STORE, aid, {
        "assessment_id": aid, "org": "default", "verdict": "NO_VALIDATED_BREACH",
        "normalized_rows": [{"row_index": 0, "user": "OWNED_SNAPSHOT_SENTINEL"}],
    })
    _record_decision("unrelated-report-decision", "VALIDATED_BREACH", .95, ["iam:kerberoasting"])
    r = TestClient(app).get(f"/api/v1/report/ingestion?assessment_id={aid}&format=json&persist=false",
                            headers={**default_test_headers(), "x-tenant-id": "default"})
    assert r.status_code == 200
    assert "OWNED_SNAPSHOT_SENTINEL" in r.text
    assert "unrelated-report-decision" not in r.text
    assert r.json()["meta"]["assessment_id"] == aid


def test_technique_citations_are_candidates_not_failures_or_legal_triggers():
    from src.analysis.framework_mapper import build_control_failure_register
    narrative = {"mitre_techniques": ["T1078"], "affected_principals": {"users": ["alice"]}}
    register = build_control_failure_register(narrative, evidence_rows=[{
        "row_index": 0, "mitre_techniques": ["T1078"], "timestamp": "2026-09-01T00:00:00Z",
    }])
    assert register["candidate_control_count"] > 0
    assert register["evidence_link_count"] > 0
    assert register["failed_control_count"] == 0
    assert register["regulatory_triggers"] == []
    assert "affected_data" not in narrative
    controls = [c for key, values in register["control_failures_by_framework"].items()
                if key != "unmapped_techniques" for c in values]
    assert all(c["evidence_refs"] == [0] and not c["failure_verified"] for c in controls)


def test_source_time_is_preserved_and_invalid_time_is_not_now():
    from src.correlation.canonical_event import CanonicalEvent
    from src.core.event_time import event_epoch
    value = "2026-09-01T00:00:00Z"
    assert CanonicalEvent.from_dict({"timestamp": value}).timestamp == event_epoch(value)
    with pytest.raises(ValueError, match="source_timestamp"):
        CanonicalEvent.from_dict({"timestamp": "invalid"})


def test_historical_projection_excludes_future_and_undated_evidence():
    from src.api.case_scope import scope_to_knowledge_time
    view = json.loads(open("tests/fixtures/case_evidence/v2.json", encoding="utf-8").read())
    view["evidence"]["rows"] = [
        {"id": "early", "known_at": "2026-09-01T00:00:00Z"},
        {"id": "late", "known_at": "2026-09-03T00:00:00Z"}, {"id": "undated"},
    ]
    result = scope_to_knowledge_time(view, "2026-09-02T00:00:00Z")
    assert [r["id"] for r in result["evidence"]["rows"]] == ["early"]
    assert result["claims"] == []
    assert result["control_impacts"] == []
    assert result["case"]["verdict"] == "ANALYSIS_INCOMPLETE"
    assert result["graph"]["edges"] == []
    assert len(view["evidence"]["rows"]) == 3
    from src.api.models.case_evidence import CaseEvidenceViewModelV2
    CaseEvidenceViewModelV2.model_validate(result)


def test_registry_covers_taxonomy_without_prefix_inheritance():
    from src.core.mappings.control_registry import registry_snapshot, factor_control_record
    from src.core.threat_modeling.factor_taxonomy import _FACTOR_MAP, _expand_controls
    records = {r["factor"]: r for r in registry_snapshot()["factors"]}
    assert set(_FACTOR_MAP) <= records.keys()
    assert all(r["tag_grade"] in {"inferred", "unmapped"} for r in records.values())
    assert factor_control_record("endpoint:invented")["controls"] == {}
    assert _expand_controls(["NIST:AC-3"]) == ["NIST:AC-3"]


def test_stream_session_owner_cannot_be_selected_by_request_body():
    from src.api.server import app
    from tests._helpers import default_test_headers
    response = TestClient(app).post('/api/v1/stream/sessions',
        json={"org": "another-tenant"}, headers={**default_test_headers(), "x-tenant-id": "default"})
    assert response.status_code == 403


def test_stream_session_lookup_rejects_other_owner(monkeypatch):
    from types import SimpleNamespace
    from src.api.streaming_endpoints import _require_session
    from src.pipeline import streaming_ingest
    from fastapi import HTTPException
    monkeypatch.setattr(streaming_ingest, "get_session", lambda _: SimpleNamespace(org="other"))
    with pytest.raises(HTTPException) as exc:
        _require_session("other-session", "default")
    assert exc.value.status_code == 404


def test_azure_cloud_adapter_preserves_actor_time_ip_and_status():
    from src.pipeline.streaming_ingest import normalize_row
    row = normalize_row({"source_type": "cloud", "userPrincipalName": "alice@example.test",
        "createdDateTime": "2026-09-01T00:00:00Z", "ipAddress": "192.0.2.10",
        "status": {"errorCode": 50074}})
    assert row['user'] == 'alice@example.test'
    assert row['src_ip'] == '192.0.2.10'
    assert row['timestamp'] == '2026-09-01T00:00:00Z'
    assert row['outcome'] == 'failure'


@pytest.mark.parametrize('suffix', ['audit-pack', 'audit-pack.csv', 'report.html', 'rows/0'])
def test_legacy_grc_routes_enforce_snapshot_owner(monkeypatch, suffix):
    from src.api.server import app
    from src.api.deep_analyze.persistence import REPORT_STORE
    from tests._helpers import default_test_headers
    aid = 'legacy-grc-other-owner'
    monkeypatch.setitem(REPORT_STORE, aid, {'org': 'other', 'audit_pack': {'secret': 'OTHER_TENANT_SENTINEL'},
                                         'evidence_rows': [{'row_index': 0, 'user': 'OTHER_TENANT_SENTINEL'}]})
    response = TestClient(app).get(f'/api/v1/assessments/{aid}/{suffix}',
        headers={**default_test_headers(), 'x-tenant-id': 'default'})
    assert response.status_code == 404
    assert 'OTHER_TENANT_SENTINEL' not in response.text
