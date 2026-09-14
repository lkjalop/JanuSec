"""One AssessmentRun DAG entry contract for every ingestion transport."""

from __future__ import annotations

import datetime as dt
import json
import os
import uuid
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
from src.repositories import evidence_ledger_repo

ASSESSMENT_RUN_VERSION = "janusec.assessment-run/v1"


def standard_dag(tenant_id: str, case_id: str, entry_kind: str) -> AssessmentDAG:
    manifests = (
        StageManifest(
            "capture", "1.0.0", ("raw_capture",), input_types=(entry_kind,), parameters={"entry_kind": entry_kind}
        ),
        StageManifest("parse", "1.0.0", ("parsed_rows",), depends_on=("capture",), input_types=("raw_capture",)),
        StageManifest("normalize", "1.0.0", ("normalized_rows",), depends_on=("parse",), input_types=("parsed_rows",)),
        StageManifest(
            "correlate", "1.0.0", ("typed_assertions",), depends_on=("normalize",), input_types=("normalized_rows",)
        ),
        StageManifest(
            "retrieve", "1.0.0", ("evidence_pack",), depends_on=("correlate",), input_types=("typed_assertions",)
        ),
        StageManifest(
            "assess", "1.0.0", ("case_assessment",), depends_on=("retrieve",), input_types=("evidence_pack",)
        ),
        StageManifest("report", "1.0.0", ("case_view",), depends_on=("assess",), input_types=("case_assessment",)),
    )
    return AssessmentDAG(tenant_id=tenant_id, case_id=case_id, manifests=manifests)


def _object_store():
    if os.getenv("EVIDENCE_OBJECT_BACKEND", "local").lower() == "s3-worm":
        return S3WORMObjectStore(
            os.getenv("EVIDENCE_S3_BUCKET", ""),
            retention_days=int(os.getenv("EVIDENCE_RETENTION_DAYS", "365")),
        )
    return LocalImmutableObjectStore()


async def register_entry(
    *,
    tenant_id: str,
    case_id: str | None,
    entry_kind: str,
    source: str,
    payload: bytes,
    source_native_id: str | None = None,
) -> dict[str, Any]:
    """Persist an immutable transport payload and open the shared DAG."""
    if not tenant_id:
        raise ValueError("tenant_id_required")
    run_id = case_id or f"assessment-{entry_kind}-{uuid.uuid4().hex[:12]}"
    dag = standard_dag(tenant_id, run_id, entry_kind)
    store = _object_store()
    legal_hold = os.getenv("EVIDENCE_LEGAL_HOLD_DEFAULT", "0").lower() in {"1", "true", "yes"}
    if isinstance(store, S3WORMObjectStore):
        stored = store.put_bytes(payload, tenant_id=tenant_id, case_id=run_id, legal_hold=legal_hold)
    else:
        stored = store.put_bytes(payload)
    now = dt.datetime.now(dt.timezone.utc)
    evidence = EvidenceRecord(
        tenant_id=tenant_id,
        case_id=run_id,
        evidence_type=f"{entry_kind}_payload",
        source=source,
        source_native_id=source_native_id or stored.sha256,
        raw_locator=stored.locator,
        raw_sha256=stored.sha256,
        occurred_at=now,
        observed_at=now,
        ingested_at=now,
        known_at=now,
        collector_version="1.0.0",
        parser_version="pending",
        mapping_version="pending",
        source_schema_version=ASSESSMENT_RUN_VERSION,
        clock_source="server_ingest_clock",
        source_timezone="UTC",
        clock_skew_seconds=0.0,
        time_uncertainty_seconds=0.0,
        acl=(f"tenant:{tenant_id}",),
        retention_policy=os.getenv("EVIDENCE_RETENTION_POLICY", "security-evidence-default"),
        classification=os.getenv("EVIDENCE_CLASSIFICATION", "restricted"),
        legal_hold=legal_hold,
        payload={"entry_kind": entry_kind, "source": source, "size": stored.size},
    )
    capture = dag.manifest("capture")
    invocation = StageInvocation.create(
        capture, tenant_id=tenant_id, case_id=run_id, input_evidence_ids=(evidence.evidence_id,)
    )
    artifact = StageArtifact(
        tenant_id=tenant_id,
        case_id=run_id,
        stage_id="capture",
        artifact_type="raw_capture",
        producer_version=capture.stage_version,
        valid_from=now,
        known_at=now,
        evidence_ids=(evidence.evidence_id,),
        payload={"entry_kind": entry_kind, "object_hash": stored.sha256},
    )
    receipt = ArtifactReceipt.issue(capture, invocation, artifact)
    await evidence_ledger_repo.append_many(
        [dag.to_dict(), evidence.to_dict(), invocation.to_dict(), artifact.to_dict(), receipt.to_dict()]
    )
    return {
        "schema_version": ASSESSMENT_RUN_VERSION,
        "assessment_run_id": run_id,
        "dag_id": dag.dag_id,
        "entry_kind": entry_kind,
        "capture_receipt_id": receipt.receipt_id,
    }


async def register_json_entry(**kwargs: Any) -> dict[str, Any]:
    document = kwargs.pop("document")
    return await register_entry(payload=json.dumps(document, sort_keys=True, separators=(",", ":")).encode(), **kwargs)


async def register_entry_safe(**kwargs: Any) -> dict[str, Any]:
    try:
        return await register_entry(**kwargs)
    except Exception as exc:
        if os.getenv("EVIDENCE_LEDGER_REQUIRED", "0").lower() in {"1", "true", "yes"}:
            raise
        return {
            "schema_version": ASSESSMENT_RUN_VERSION,
            "assessment_run_id": kwargs.get("case_id"),
            "entry_kind": kwargs.get("entry_kind"),
            "custody_status": "degraded",
            "custody_error": type(exc).__name__,
        }


async def register_json_entry_safe(**kwargs: Any) -> dict[str, Any]:
    try:
        return await register_json_entry(**kwargs)
    except Exception as exc:
        if os.getenv("EVIDENCE_LEDGER_REQUIRED", "0").lower() in {"1", "true", "yes"}:
            raise
        return {
            "schema_version": ASSESSMENT_RUN_VERSION,
            "assessment_run_id": kwargs.get("case_id"),
            "entry_kind": kwargs.get("entry_kind"),
            "custody_status": "degraded",
            "custody_error": type(exc).__name__,
        }


__all__ = [
    "ASSESSMENT_RUN_VERSION",
    "register_entry",
    "register_json_entry",
    "register_entry_safe",
    "register_json_entry_safe",
    "standard_dag",
]
