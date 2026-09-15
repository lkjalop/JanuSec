"""Evidence Contract v1 adapter around the real capture/parse/normalize boundary."""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os
from pathlib import Path
from typing import Any

from src.core.evidence_contract import (
    ArtifactReceipt,
    AssessmentDAG,
    EvidenceRecord,
    LocalImmutableObjectStore,
    S3WORMObjectStore,
    StageArtifact,
    StageInvocation,
    StageManifest,
)
from src.core.evidence_contract.metrics import EVIDENCE_KERNEL_DEGRADED
from src.repositories import evidence_ledger_repo

logger = logging.getLogger(__name__)
VERSION = "1.0.0"


def manifests() -> tuple[StageManifest, StageManifest, StageManifest]:
    capture = StageManifest(
        stage_id="capture", stage_version=VERSION, input_types=("source_file",), output_types=("raw_capture",)
    )
    parse = StageManifest(
        stage_id="parse",
        stage_version=VERSION,
        depends_on=("capture",),
        input_types=("raw_capture",),
        output_types=("parsed_rows",),
    )
    normalize = StageManifest(
        stage_id="normalize",
        stage_version=VERSION,
        depends_on=("parse",),
        input_types=("parsed_rows",),
        output_types=("normalized_rows",),
    )
    return capture, parse, normalize


async def capture_inputs(tenant_id: str, case_id: str, file_paths: list[tuple[str, str]]) -> dict[str, Any]:
    """Capture raw bytes first, then append evidence and a capture receipt."""
    capture, parse, normalize = manifests()
    dag = AssessmentDAG(tenant_id=tenant_id, case_id=case_id, manifests=(capture, parse, normalize))
    object_backend = os.getenv("EVIDENCE_OBJECT_BACKEND", "local").lower()
    if object_backend == "s3-worm":
        store = S3WORMObjectStore(
            os.getenv("EVIDENCE_S3_BUCKET", ""),
            retention_days=int(os.getenv("EVIDENCE_RETENTION_DAYS", "365")),
        )
    else:
        store = LocalImmutableObjectStore()
    legal_hold = os.getenv("EVIDENCE_LEGAL_HOLD_DEFAULT", "0").lower() in {"1", "true", "yes"}
    evidence: list[EvidenceRecord] = []
    for path, filename in file_paths:
        if isinstance(store, S3WORMObjectStore):
            stored = await asyncio.to_thread(
                store.put_file,
                path,
                tenant_id=tenant_id,
                case_id=case_id,
                legal_hold=legal_hold,
            )
        else:
            stored = await asyncio.to_thread(store.put_file, path)
        timestamp = dt.datetime.now(dt.timezone.utc)
        evidence.append(
            EvidenceRecord(
                tenant_id=tenant_id,
                case_id=case_id,
                evidence_type="raw_file",
                source="assessment_upload",
                source_native_id=filename,
                raw_locator=stored.locator,
                raw_sha256=stored.sha256,
                occurred_at=timestamp,
                observed_at=timestamp,
                ingested_at=timestamp,
                known_at=timestamp,
                collector_version=VERSION,
                parser_version="pending",
                mapping_version="pending",
                source_schema_version="opaque/v1",
                clock_source="server_capture_clock",
                source_timezone="UTC",
                clock_skew_seconds=0.0,
                time_uncertainty_seconds=0.0,
                acl=(f"tenant:{tenant_id}",),
                retention_policy=os.getenv("EVIDENCE_RETENTION_POLICY", "security-evidence-default"),
                classification=os.getenv("EVIDENCE_CLASSIFICATION", "restricted"),
                legal_hold=legal_hold,
                payload={"filename": filename, "size": stored.size},
            )
        )
    invocation = StageInvocation.create(
        capture, tenant_id=tenant_id, case_id=case_id, input_evidence_ids=tuple(item.evidence_id for item in evidence)
    )
    now = dt.datetime.now(dt.timezone.utc)
    artifact = StageArtifact(
        tenant_id=tenant_id,
        case_id=case_id,
        stage_id="capture",
        artifact_type="raw_capture",
        producer_version=VERSION,
        valid_from=now,
        known_at=now,
        evidence_ids=tuple(item.evidence_id for item in evidence),
        payload={"object_count": len(evidence), "object_hashes": [item.raw_sha256 for item in evidence]},
    )
    receipt = ArtifactReceipt.issue(capture, invocation, artifact)
    # The DAG embeds the global stage manifests while preserving tenant/case
    # scope. Standalone manifests are deliberately not tenant-owned records.
    await evidence_ledger_repo.append_many(
        [
            dag.to_dict(),
            *(item.to_dict() for item in evidence),
            invocation.to_dict(),
            artifact.to_dict(),
            receipt.to_dict(),
        ]
    )
    return {"dag": dag.to_dict(), "capture_artifact": artifact, "evidence": evidence, "receipts": [receipt.to_dict()]}


async def record_parse_normalize(
    tenant_id: str, case_id: str, capture_context: dict[str, Any], *, row_count: int, source_count: int
) -> dict[str, Any]:
    capture, parse, normalize = manifests()
    capture_artifact: StageArtifact = capture_context["capture_artifact"]
    now = dt.datetime.now(dt.timezone.utc)
    parse_invocation = StageInvocation.create(
        parse, tenant_id=tenant_id, case_id=case_id, input_artifact_ids=(capture_artifact.artifact_id,)
    )
    parsed = StageArtifact(
        tenant_id=tenant_id,
        case_id=case_id,
        stage_id="parse",
        artifact_type="parsed_rows",
        producer_version=VERSION,
        valid_from=now,
        known_at=now,
        input_artifact_ids=(capture_artifact.artifact_id,),
        evidence_ids=tuple(item.evidence_id for item in capture_context["evidence"]),
        payload={"row_count": row_count, "source_count": source_count},
    )
    parse_receipt = ArtifactReceipt.issue(parse, parse_invocation, parsed)
    normalize_invocation = StageInvocation.create(
        normalize, tenant_id=tenant_id, case_id=case_id, input_artifact_ids=(parsed.artifact_id,)
    )
    normalized = StageArtifact(
        tenant_id=tenant_id,
        case_id=case_id,
        stage_id="normalize",
        artifact_type="normalized_rows",
        producer_version=VERSION,
        valid_from=now,
        known_at=now,
        input_artifact_ids=(parsed.artifact_id,),
        evidence_ids=parsed.evidence_ids,
        payload={"row_count": row_count, "normalization_contract": "janusec-normalized-row/current"},
    )
    normalize_receipt = ArtifactReceipt.issue(normalize, normalize_invocation, normalized)
    records = [
        parse_invocation.to_dict(),
        parsed.to_dict(),
        parse_receipt.to_dict(),
        normalize_invocation.to_dict(),
        normalized.to_dict(),
        normalize_receipt.to_dict(),
    ]
    await evidence_ledger_repo.append_many(records)
    return {
        "assessment_dag": capture_context["dag"],
        "stage_receipts": [*capture_context["receipts"], parse_receipt.to_dict(), normalize_receipt.to_dict()],
    }


async def safely_capture(tenant_id: str, case_id: str, file_paths: list[tuple[str, str]]) -> dict[str, Any] | None:
    try:
        result = await capture_inputs(tenant_id, case_id, file_paths)
        EVIDENCE_KERNEL_DEGRADED.set(0)
        return result
    except Exception:
        EVIDENCE_KERNEL_DEGRADED.set(1)
        if os.getenv("EVIDENCE_LEDGER_REQUIRED", "0").lower() in {"1", "true", "yes"}:
            raise
        logger.exception("evidence ledger capture degraded for %s", case_id)
        return None


__all__ = ["capture_inputs", "manifests", "record_parse_normalize", "safely_capture"]
