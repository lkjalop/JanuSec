from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from src.core.evidence_contract import (
    AssertionRecord,
    AssertionType,
    ContractValidationError,
    EvidenceRecord,
    StageArtifact,
)

VALID_FROM = datetime(2026, 8, 17, 10, 30, tzinfo=timezone.utc)
KNOWN_AT = datetime(2026, 8, 17, 10, 35, tzinfo=timezone.utc)


def _evidence(**overrides: object) -> EvidenceRecord:
    values = {
        "tenant_id": "tenant-a",
        "case_id": "case-42",
        "evidence_type": "network.connection",
        "source": "zeek",
        "source_native_id": "zeek:conn:000042",
        "raw_locator": "evidence://capture-7/conn.log",
        "raw_sha256": "a" * 64,
        "raw_offset": 8192,
        "occurred_at": VALID_FROM,
        "observed_at": VALID_FROM + timedelta(seconds=1),
        "ingested_at": VALID_FROM + timedelta(seconds=2),
        "known_at": KNOWN_AT,
        "collector_version": "zeek-collector/2.4.1",
        "parser_version": "zeek-tsv/1.3.0",
        "mapping_version": "ocsf-network/1.1.0",
        "source_schema_version": "zeek.conn/5.2",
        "clock_source": "sensor_ntp",
        "source_timezone": "UTC",
        "clock_skew_seconds": -0.25,
        "time_uncertainty_seconds": 0.5,
        "acl": ("tenant:tenant-a", "role:analyst"),
        "retention_policy": "incident-evidence-7y",
        "classification": "confidential",
        "legal_hold": False,
        "payload": {"dst_ip": "203.0.113.8", "ports": [443, 8443], "score": 0.91},
    }
    values.update(overrides)
    return EvidenceRecord(**values)  # type: ignore[arg-type]


def test_evidence_identity_is_canonical_across_key_order_and_timezones() -> None:
    first = _evidence(payload={"z": [2, 1], "a": {"user": "alice"}})
    second = _evidence(
        occurred_at=datetime(2026, 8, 17, 20, 30, tzinfo=timezone(timedelta(hours=10))),
        observed_at=datetime(2026, 8, 17, 20, 30, 1, tzinfo=timezone(timedelta(hours=10))),
        ingested_at=datetime(2026, 8, 17, 20, 30, 2, tzinfo=timezone(timedelta(hours=10))),
        known_at=datetime(2026, 8, 17, 20, 35, tzinfo=timezone(timedelta(hours=10))),
        payload={"a": {"user": "alice"}, "z": [2, 1]},
    )

    assert first.evidence_id == second.evidence_id
    assert first.content_hash == second.content_hash
    assert first.evidence_id == f"ev1_{first.content_hash}"


def test_scope_is_part_of_evidence_identity() -> None:
    original = _evidence()

    assert _evidence(tenant_id="tenant-b").evidence_id != original.evidence_id
    assert _evidence(case_id="case-43").evidence_id != original.evidence_id


def test_evidence_audit_provenance_and_four_times_are_explicit_and_hashed() -> None:
    record = _evidence()
    raw = record.to_dict()

    assert raw["source_native_id"] == "zeek:conn:000042"
    assert raw["raw_locator"] == "evidence://capture-7/conn.log"
    assert raw["raw_sha256"] == "a" * 64
    assert raw["raw_offset"] == 8192
    assert raw["occurred_at"] < raw["observed_at"] < raw["ingested_at"] < raw["known_at"]
    assert record.valid_from == record.occurred_at
    for field in ("collector_version", "parser_version", "mapping_version", "source_schema_version"):
        assert raw[field]
    assert raw["clock_source"] == "sensor_ntp"
    assert raw["source_timezone"] == "UTC"
    assert raw["clock_skew_seconds"] == -0.25
    assert raw["time_uncertainty_seconds"] == 0.5
    assert raw["acl"] == ["role:analyst", "tenant:tenant-a"]
    assert raw["retention_policy"] == "incident-evidence-7y"
    assert raw["classification"] == "confidential"
    assert raw["legal_hold"] is False

    assert _evidence(source_native_id="zeek:conn:000043").evidence_id != record.evidence_id
    assert _evidence(parser_version="zeek-tsv/1.3.1").evidence_id != record.evidence_id


def test_records_are_deeply_immutable() -> None:
    record = _evidence(payload={"nested": {"value": 1}, "items": ["a", "b"]})

    with pytest.raises(FrozenInstanceError):
        record.source = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        record.payload["new"] = "value"  # type: ignore[index]
    with pytest.raises(TypeError):
        record.payload["nested"]["value"] = 2  # type: ignore[index]
    assert record.payload["items"] == ("a", "b")
    assert hash(record) == hash(record.evidence_id)


def test_evidence_serialization_round_trip_verifies_hashes() -> None:
    original = _evidence(valid_to=VALID_FROM + timedelta(minutes=3))
    raw = original.to_dict()

    assert EvidenceRecord.from_dict(raw) == original
    json.dumps(raw)  # The transport form remains plain JSON.

    raw["payload"]["score"] = 0.01
    with pytest.raises(ContractValidationError, match="content_hash"):
        EvidenceRecord.from_dict(raw)


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"occurred_at": datetime(2026, 8, 17, 10, 30)}, "timezone-aware"),
        ({"valid_to": VALID_FROM - timedelta(seconds=1)}, "valid_to"),
        ({"known_at": VALID_FROM, "ingested_at": VALID_FROM + timedelta(seconds=1)}, "known_at"),
        ({"raw_sha256": "not-a-digest"}, "SHA-256"),
        ({"raw_offset": -1}, "raw_offset"),
        ({"clock_skew_seconds": float("inf")}, "clock_skew_seconds"),
        ({"time_uncertainty_seconds": -0.1}, "time_uncertainty_seconds"),
        ({"acl": ()}, "acl"),
        ({"legal_hold": "false"}, "legal_hold"),
        ({"payload": {"bad": float("nan")}}, "non-finite"),
        ({"payload": {"bad": {"unordered"}}}, "unsupported"),
        ({"tenant_id": "  "}, "tenant_id"),
    ],
)
def test_evidence_rejects_ambiguous_or_non_json_contract_values(
    overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(ContractValidationError, match=message):
        _evidence(**overrides)


def test_assertion_is_typed_bitemporal_and_normalises_support_ids() -> None:
    assertion = AssertionRecord(
        tenant_id="tenant-a",
        case_id="case-42",
        assertion_type="inferred",
        subject="identity:alice",
        predicate="authenticated_from",
        object_value={"ip": "203.0.113.8", "risk": ["rare_asn"]},
        valid_from=VALID_FROM,
        known_at=KNOWN_AT,
        analyzer_id="identity-resolution",
        analyzer_version="2.1.0",
        evidence_ids=("ev-b", "ev-a", "ev-a"),
        contradicting_evidence_ids=("ev-z",),
        supersedes_assertion_ids=("as-old",),
        confidence=0.82,
        attributes={"method": "deterministic_rule"},
    )

    assert assertion.evidence_ids == ("ev-a", "ev-b")
    assert assertion.contradicting_evidence_ids == ("ev-z",)
    assert assertion.supersedes_assertion_ids == ("as-old",)
    assert assertion.assertion_type is AssertionType.INFERRED
    assert assertion.object_value["risk"] == ("rare_asn",)
    assert assertion.assertion_id == f"as1_{assertion.content_hash}"
    assert AssertionRecord.from_dict(assertion.to_dict()) == assertion

    with pytest.raises(ContractValidationError, match="confidence"):
        AssertionRecord(
            tenant_id="tenant-a",
            case_id="case-42",
            assertion_type="inferred",
            subject="identity:alice",
            predicate="authenticated_from",
            object_value="203.0.113.8",
            valid_from=VALID_FROM,
            known_at=KNOWN_AT,
            analyzer_id="identity-resolution",
            analyzer_version="2.1.0",
            confidence=1.01,
        )


def test_assertion_type_analyzer_contradictions_and_supersession_are_auditable() -> None:
    common = {
        "tenant_id": "tenant-a",
        "case_id": "case-42",
        "assertion_type": "observed",
        "subject": "host:endpoint-7",
        "predicate": "executed",
        "object_value": "powershell.exe",
        "valid_from": VALID_FROM,
        "known_at": KNOWN_AT,
        "analyzer_id": "process-observer",
        "analyzer_version": "3.0.0",
        "evidence_ids": ("ev-support",),
        "contradicting_evidence_ids": ("ev-denial",),
        "supersedes_assertion_ids": ("as-prior",),
    }
    assertion = AssertionRecord(**common)  # type: ignore[arg-type]

    assert assertion.to_dict()["assertion_type"] == "observed"
    assert AssertionRecord(**{**common, "analyzer_version": "3.0.1"}).assertion_id != assertion.assertion_id  # type: ignore[arg-type]
    with pytest.raises(ContractValidationError, match="assertion_type"):
        AssertionRecord(**{**common, "assertion_type": "fact"})  # type: ignore[arg-type]
    with pytest.raises(ContractValidationError, match="simultaneously support and contradict"):
        AssertionRecord(**{**common, "contradicting_evidence_ids": ("ev-support",)})  # type: ignore[arg-type]


def test_stage_artifact_identity_covers_inputs_provenance_and_payload() -> None:
    common = {
        "tenant_id": "tenant-a",
        "case_id": "case-42",
        "stage_id": "correlate",
        "artifact_type": "correlation_set",
        "producer_version": "1.2.0",
        "valid_from": VALID_FROM,
        "known_at": KNOWN_AT,
        "payload": {"edges": [{"from": "alice", "to": "203.0.113.8"}]},
        "input_artifact_ids": ("sa-b", "sa-a"),
        "evidence_ids": ("ev-b", "ev-a"),
        "assertion_ids": ("as-1",),
    }
    first = StageArtifact(**common)  # type: ignore[arg-type]
    second = StageArtifact(**{**common, "input_artifact_ids": ("sa-a", "sa-b")})  # type: ignore[arg-type]

    assert first.artifact_id == second.artifact_id
    assert first.input_artifact_ids == ("sa-a", "sa-b")
    assert StageArtifact.from_dict(first.to_dict()) == first
    assert StageArtifact(**{**common, "payload": {"edges": []}}).artifact_id != first.artifact_id  # type: ignore[arg-type]
