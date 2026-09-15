from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from src.core.evidence_contract import (
    ArtifactReceipt,
    AssessmentDAG,
    ContractValidationError,
    DAGValidationError,
    ReceiptBook,
    ReceiptConflictError,
    StageArtifact,
    StageInvocation,
    StageManifest,
    StageStatus,
    StageStatusRecord,
    derive_replay_key,
)

NOW = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)


def _manifests() -> tuple[StageManifest, ...]:
    return (
        StageManifest("assess", "1.0.0", ("assessment",), ("correlate", "timeline"), ("links", "timeline")),
        StageManifest("timeline", "1.0.0", ("timeline",), ("normalize",), ("normalized",)),
        StageManifest("normalize", "1.0.0", ("normalized",), parameters={"mapping": "ocsf-v1"}),
        StageManifest("correlate", "1.1.0", ("links",), ("normalize",), ("normalized",)),
    )


def _dag() -> AssessmentDAG:
    return AssessmentDAG("tenant-a", "case-42", _manifests())


def _artifact(
    manifest: StageManifest,
    artifact_type: str | None = None,
    *,
    payload: dict[str, object] | None = None,
    input_ids: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = ("ev-source",),
) -> StageArtifact:
    return StageArtifact(
        tenant_id="tenant-a",
        case_id="case-42",
        stage_id=manifest.stage_id,
        artifact_type=artifact_type or manifest.output_types[0],
        producer_version=manifest.stage_version,
        valid_from=NOW,
        known_at=NOW + timedelta(seconds=1),
        payload=payload or {"stage": manifest.stage_id},
        input_artifact_ids=input_ids,
        evidence_ids=evidence_ids,
    )


def _invocation(
    manifest: StageManifest,
    *,
    input_ids: tuple[str, ...] = (),
    input_evidence_ids: tuple[str, ...] = ("ev-input",),
    input_assertion_ids: tuple[str, ...] = (),
) -> StageInvocation:
    return StageInvocation.create(
        manifest,
        tenant_id="tenant-a",
        case_id="case-42",
        input_artifact_ids=input_ids,
        input_evidence_ids=input_evidence_ids,
        input_assertion_ids=input_assertion_ids,
    )


def test_dag_validates_and_orders_deterministically() -> None:
    dag = _dag()
    reordered = AssessmentDAG("tenant-a", "case-42", tuple(reversed(_manifests())))

    assert dag.topological_order == ("normalize", "correlate", "timeline", "assess")
    assert tuple(manifest.stage_id for manifest in dag.manifests) == dag.topological_order
    assert reordered.dag_id == dag.dag_id
    assert dag.manifest("correlate").depends_on == ("normalize",)
    json.dumps(dag.to_dict())
    assert AssessmentDAG.from_dict(dag.to_dict()) == dag


def test_manifest_hash_is_canonical_and_contract_is_immutable() -> None:
    first = StageManifest(
        "correlate",
        "1.0.0",
        ("links", "scores"),
        ("enrich", "normalize"),
        parameters={"weights": {"time": 0.7, "identity": 0.3}},
    )
    second = StageManifest(
        "correlate",
        "1.0.0",
        ("scores", "links"),
        ("normalize", "enrich"),
        parameters={"weights": {"identity": 0.3, "time": 0.7}},
    )

    assert first.manifest_hash == second.manifest_hash
    with pytest.raises(TypeError):
        first.parameters["new"] = True  # type: ignore[index]

    persisted = first.to_dict()
    assert StageManifest.from_dict(persisted) == first
    persisted["parameters"]["weights"]["time"] = 0.2
    with pytest.raises(ContractValidationError, match="manifest_hash"):
        StageManifest.from_dict(persisted)


def test_dag_rejects_missing_dependencies_duplicates_and_cycles() -> None:
    with pytest.raises(DAGValidationError, match="missing stage dependencies: missing"):
        AssessmentDAG("tenant-a", "case-42", (StageManifest("a", "1", ("out",), ("missing",)),))

    duplicate = StageManifest("same", "1", ("out",))
    with pytest.raises(DAGValidationError, match="duplicate stage_id"):
        AssessmentDAG("tenant-a", "case-42", (duplicate, duplicate))

    cyclic = (
        StageManifest("a", "1", ("a-out",), ("c",)),
        StageManifest("b", "1", ("b-out",), ("a",)),
        StageManifest("c", "1", ("c-out",), ("b",)),
    )
    with pytest.raises(DAGValidationError, match=r"cycle: .* -> .* -> .* ->"):
        AssessmentDAG("tenant-a", "case-42", cyclic)


def test_ready_scheduler_respects_dependencies_status_and_retry_policy() -> None:
    dag = _dag()

    assert [stage.stage_id for stage in dag.ready_stages()] == ["normalize"]
    assert [stage.stage_id for stage in dag.ready_stages({"normalize": "succeeded"})] == [
        "correlate",
        "timeline",
    ]
    assert [
        stage.stage_id
        for stage in dag.ready_stages(
            {"normalize": StageStatus.SUCCEEDED, "correlate": StageStatus.SUCCEEDED, "timeline": "succeeded"}
        )
    ] == ["assess"]
    assert dag.ready_stages({"normalize": StageStatus.FAILED}) == ()
    assert [stage.stage_id for stage in dag.ready_stages({"normalize": StageStatus.FAILED}, retry_failed=True)] == [
        "normalize"
    ]
    assert [stage.stage_id for stage in dag.ready_stages({"normalize": "succeeded"}, limit=1)] == ["correlate"]


def test_status_records_have_stable_run_identity_and_are_scope_checked() -> None:
    dag = _dag()
    manifest = dag.manifest("normalize")
    pending = StageStatusRecord(
        tenant_id="tenant-a",
        case_id="case-42",
        stage_id="normalize",
        manifest_hash=manifest.manifest_hash,
        run_key="replay-1",
        status=StageStatus.RUNNING,
        known_at=NOW,
    )
    complete = StageStatusRecord(
        tenant_id="tenant-a",
        case_id="case-42",
        stage_id="normalize",
        manifest_hash=manifest.manifest_hash,
        run_key="replay-1",
        status=StageStatus.SUCCEEDED,
        known_at=NOW + timedelta(seconds=5),
        output_artifact_ids=("sa-1",),
    )

    assert pending.run_id == complete.run_id
    assert pending.status_record_id != complete.status_record_id
    assert [stage.stage_id for stage in dag.ready_stages({"normalize": complete})] == ["correlate", "timeline"]
    json.dumps(complete.to_dict())
    assert StageStatusRecord.from_dict(complete.to_dict()) == complete

    tampered = complete.to_dict()
    tampered["status"] = "failed"
    with pytest.raises(ContractValidationError, match="content_hash"):
        StageStatusRecord.from_dict(tampered)

    wrong_scope = StageStatusRecord(
        tenant_id="tenant-b",
        case_id="case-42",
        stage_id="normalize",
        manifest_hash=manifest.manifest_hash,
        run_key="replay-1",
        status=StageStatus.SUCCEEDED,
        known_at=NOW,
    )
    with pytest.raises(DAGValidationError, match="tenant/case"):
        dag.ready_stages({"normalize": wrong_scope})


def test_artifact_receipts_are_deterministic_and_idempotent() -> None:
    manifest = _dag().manifest("normalize")
    artifact = _artifact(manifest)
    invocation = _invocation(manifest)
    first = ArtifactReceipt.issue(manifest, invocation, artifact)
    second = ArtifactReceipt.issue(manifest, invocation, artifact)
    book = ReceiptBook("tenant-a", "case-42")

    assert first == second
    assert first.receipt_id == second.receipt_id
    assert first.replay_key == derive_replay_key(manifest, invocation)
    assert book.record(first) is first
    assert book.record(second) is first
    assert len(book) == 1
    assert book.receipts() == (first,)
    assert StageInvocation.from_dict(invocation.to_dict()) == invocation
    assert ArtifactReceipt.from_dict(first.to_dict()) == first


def test_pre_execution_invocation_separates_inputs_from_output_lineage() -> None:
    manifest = _dag().manifest("normalize")
    invocation = _invocation(manifest, input_evidence_ids=("ev-raw-input",))
    output_a = _artifact(manifest, evidence_ids=("ev-derived-a",))
    output_b = _artifact(manifest, evidence_ids=("ev-derived-b",))
    receipt_a = ArtifactReceipt.issue(manifest, invocation, output_a)
    receipt_b = ArtifactReceipt.issue(manifest, invocation, output_b)
    book = ReceiptBook("tenant-a", "case-42")

    assert receipt_a.receipt_id == receipt_b.receipt_id
    assert receipt_a.replay_key == receipt_b.replay_key == invocation.replay_key
    assert output_a.artifact_id != output_b.artifact_id
    book.record(receipt_a)
    with pytest.raises(ReceiptConflictError, match="different artifact"):
        book.record(receipt_b)

    changed_input = _invocation(manifest, input_evidence_ids=("ev-other-input",))
    assert changed_input.replay_key != invocation.replay_key


def test_receipt_book_detects_divergent_replay_output() -> None:
    manifest = _dag().manifest("normalize")
    original = _artifact(manifest, payload={"rows": [1]})
    divergent = _artifact(manifest, payload={"rows": [2]})
    invocation = _invocation(manifest)
    original_receipt = ArtifactReceipt.issue(manifest, invocation, original)
    divergent_receipt = ArtifactReceipt.issue(manifest, invocation, divergent)
    book = ReceiptBook("tenant-a", "case-42")

    assert original_receipt.receipt_id == divergent_receipt.receipt_id
    assert original_receipt.artifact_id != divergent_receipt.artifact_id
    book.record(original_receipt)
    with pytest.raises(ReceiptConflictError, match="different artifact"):
        book.record(divergent_receipt)


def test_persisted_receipt_verification_rejects_tampering() -> None:
    manifest = _dag().manifest("normalize")
    artifact = _artifact(manifest)
    invocation = _invocation(manifest)
    receipt = ArtifactReceipt.issue(manifest, invocation, artifact)
    tampered = receipt.to_dict()
    tampered["artifact_hash"] = "b" * 64

    with pytest.raises(ContractValidationError, match="content_hash"):
        ArtifactReceipt.from_dict(tampered)


def test_receipt_issue_enforces_manifest_output_contract() -> None:
    manifest = _dag().manifest("normalize")
    invocation = _invocation(manifest)
    undeclared = _artifact(manifest, artifact_type="unexpected")
    wrong_version = StageArtifact(
        tenant_id="tenant-a",
        case_id="case-42",
        stage_id="normalize",
        artifact_type="normalized",
        producer_version="old",
        valid_from=NOW,
        known_at=NOW,
        payload={},
    )

    with pytest.raises(ContractValidationError, match="artifact_type"):
        ArtifactReceipt.issue(manifest, invocation, undeclared)
    with pytest.raises(ContractValidationError, match="producer_version"):
        ArtifactReceipt.issue(manifest, invocation, wrong_version)


def test_receipts_make_dag_replay_scheduling_topological() -> None:
    dag = _dag()
    normalize = dag.manifest("normalize")
    normalized = _artifact(normalize)
    normalize_invocation = _invocation(normalize)
    receipts = [ArtifactReceipt.issue(normalize, normalize_invocation, normalized)]

    assert [stage.stage_id for stage in dag.ready_from_receipts(receipts)] == ["correlate", "timeline"]

    correlate = dag.manifest("correlate")
    timeline = dag.manifest("timeline")
    linked = _artifact(correlate, input_ids=(normalized.artifact_id,))
    ordered = _artifact(timeline, input_ids=(normalized.artifact_id,))
    correlate_invocation = _invocation(correlate, input_ids=(normalized.artifact_id,), input_evidence_ids=())
    timeline_invocation = _invocation(timeline, input_ids=(normalized.artifact_id,), input_evidence_ids=())
    receipts.extend(
        (
            ArtifactReceipt.issue(correlate, correlate_invocation, linked),
            ArtifactReceipt.issue(timeline, timeline_invocation, ordered),
        )
    )

    assert [stage.stage_id for stage in dag.ready_from_receipts(receipts)] == ["assess"]


def test_partial_multi_output_receipts_do_not_mark_stage_complete() -> None:
    root = StageManifest("root", "1", ("normalized", "profile"))
    child = StageManifest("child", "1", ("decision",), ("root",), ("normalized", "profile"))
    dag = AssessmentDAG("tenant-a", "case-42", (child, root))
    normalized = _artifact(root, "normalized")
    profile = _artifact(root, "profile")
    invocation = _invocation(root)

    assert [
        stage.stage_id for stage in dag.ready_from_receipts([ArtifactReceipt.issue(root, invocation, normalized)])
    ] == ["root"]
    assert [
        stage.stage_id
        for stage in dag.ready_from_receipts(
            [ArtifactReceipt.issue(root, invocation, normalized), ArtifactReceipt.issue(root, invocation, profile)]
        )
    ] == ["child"]
