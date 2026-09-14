from datetime import datetime, timezone

from src.core.evidence_contract.chronology import compile_case_chronology, parse_event_time
from src.core.evidence_contract.projection_builder import evidence_id_for_row
from src.core.evidence_contract.semantic_adapters import normalize_semantics


def _evidence_id(assessment_id, row):
    return evidence_id_for_row(assessment_id, 0, normalize_semantics(dict(row)))


def test_same_instant_epoch_and_iso_are_equal_utc():
    instant = datetime(2026, 8, 19, 9, 11, tzinfo=timezone.utc)
    epoch = parse_event_time(instant.timestamp())
    iso = parse_event_time("2026-08-19T09:11:00Z")
    assert epoch["occurred_at"] == iso["occurred_at"] == "2026-08-19T09:11:00Z"


def test_undated_evidence_is_unsequenced_and_never_gets_sentinel_time():
    chronology = compile_case_chronology(
        tenant_id="tenant-a", assessment_id="assessment-a", case_id="case-a",
        rows=[{"row_index": 7, "summary": "credential activity", "user": "alex"}],
    )
    assert chronology["milestones"] == []
    assert len(chronology["unsequenced"]) == 1
    assert chronology["unsequenced"][0]["occurred_at"] is None


def test_temporal_adjacency_is_not_causality_and_denial_is_preserved():
    rows = [
        {"row_index": 1, "timestamp": "2026-08-19T09:00:00Z", "summary": "scan", "user": "james"},
        {"row_index": 2, "timestamp": "2026-08-19T09:40:00Z", "summary": "GetObject", "user": "wei", "eventName": "GetObject", "_result": "DENIED", "resource_id": "bucket/key"},
    ]
    chronology = compile_case_chronology(
        tenant_id="tenant-a", assessment_id="assessment-a", case_id="case-a", rows=rows,
    )
    assert chronology["milestones"][0]["enables_phase_id"] is None
    assert chronology["milestones"][0]["relation_to_next"] == "temporal_precedes"
    assert chronology["milestones"][1]["action_outcome"] == "denied"
    assert not any(item["relation_type"] == "observed_causal" for item in chronology["relations"])


def test_case_allowlist_rejects_cross_partition_rows():
    james = {"row_index": 10, "timestamp": "2026-08-19T09:00:00Z", "summary": "powershell", "user": "james"}
    wei = {"row_index": 20, "timestamp": "2026-08-19T09:01:00Z", "summary": "download", "user": "wei"}
    allowed = {_evidence_id("assessment-a", james)}
    chronology = compile_case_chronology(
        tenant_id="tenant-a", assessment_id="assessment-a", case_id="case-james",
        rows=[james, wei], allowed_evidence_ids=allowed,
    )
    assert len(chronology["milestones"]) == 1
    assert chronology["milestones"][0]["actor"] == "james"


def test_keyword_mitre_is_candidate_not_observed():
    chronology = compile_case_chronology(
        tenant_id="tenant-a", assessment_id="assessment-a", case_id="case-a",
        rows=[{"timestamp": "2026-08-19T09:00:00Z", "summary": "mimikatz credential dump", "user": "alex"}],
    )
    milestone = chronology["milestones"][0]
    assert milestone["mitre_techniques"] == []
    assert "T1003" in milestone["candidate_mitre_techniques"]


def test_denied_action_does_not_create_successful_relationship():
    chronology = compile_case_chronology(
        tenant_id="tenant-a",
        assessment_id="assessment-a",
        case_id="case-a",
        rows=[{
            "timestamp": "2026-05-01T10:00:00Z",
            "user": "alice",
            "target_resource": "restricted-bucket",
            "action": "GetObject",
            "result": "AccessDenied",
            "action_direction": "principal_to_cloud_object",
        }],
    )

    assert chronology["milestones"][0]["action_outcome"] == "denied"
    assert chronology["relations"] == []
