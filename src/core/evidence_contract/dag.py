"""Replayable, persistence-neutral assessment DAG primitives."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any

from .records import (
    CONTRACT_VERSION,
    ContractValidationError,
    JsonValue,
    StageArtifact,
    _freeze_mapping,
    _normalise_ids,
    _normalise_time,
    _parse_time,
    _require_text,
    _thaw_json,
    _time_text,
    _verify_serialized,
    canonical_hash,
)


class DAGValidationError(ValueError):
    """Raised when an assessment graph or its runtime state is invalid."""


class ReceiptConflictError(ValueError):
    """Raised when one replay slot produces two different artifacts."""


class StageStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class StageManifest:
    """Versioned declaration of a deterministic assessment stage."""

    stage_id: str
    stage_version: str
    output_types: tuple[str, ...]
    depends_on: tuple[str, ...] = ()
    input_types: tuple[str, ...] = ()
    parameters: Mapping[str, JsonValue] = field(default_factory=dict)
    manifest_hash: str = field(init=False)

    schema_version = CONTRACT_VERSION
    record_type = "stage_manifest"

    def __post_init__(self) -> None:
        object.__setattr__(self, "stage_id", _require_text(self.stage_id, "stage_id"))
        object.__setattr__(self, "stage_version", _require_text(self.stage_version, "stage_version"))
        object.__setattr__(self, "depends_on", _normalise_ids(self.depends_on, "depends_on"))
        object.__setattr__(self, "input_types", _normalise_ids(self.input_types, "input_types"))
        object.__setattr__(self, "output_types", _normalise_ids(self.output_types, "output_types"))
        if not self.output_types:
            raise ContractValidationError("output_types must contain at least one artifact type")
        object.__setattr__(self, "parameters", _freeze_mapping(self.parameters, "parameters"))
        object.__setattr__(self, "manifest_hash", canonical_hash(self._content_document()))

    def _content_document(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "stage_id": self.stage_id,
            "stage_version": self.stage_version,
            "depends_on": list(self.depends_on),
            "input_types": list(self.input_types),
            "output_types": list(self.output_types),
            "parameters": _thaw_json(self.parameters),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content_document(), "manifest_hash": self.manifest_hash}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> StageManifest:
        if raw.get("schema_version") != CONTRACT_VERSION:
            raise ContractValidationError("unsupported schema_version")
        if raw.get("record_type") != cls.record_type:
            raise ContractValidationError("record_type does not match stage manifest")
        manifest = cls(
            stage_id=raw["stage_id"],
            stage_version=raw["stage_version"],
            output_types=tuple(raw.get("output_types", ())),
            depends_on=tuple(raw.get("depends_on", ())),
            input_types=tuple(raw.get("input_types", ())),
            parameters=raw.get("parameters", {}),
        )
        supplied_hash = raw.get("manifest_hash")
        if supplied_hash is None:
            raise ContractValidationError("persisted manifest is missing manifest_hash")
        if supplied_hash != manifest.manifest_hash:
            raise ContractValidationError("manifest_hash does not match manifest content")
        return manifest

    def __hash__(self) -> int:
        return hash(self.manifest_hash)


@dataclass(frozen=True, slots=True)
class StageStatusRecord:
    """Immutable status snapshot for one stage run."""

    tenant_id: str
    case_id: str
    stage_id: str
    manifest_hash: str
    run_key: str
    status: StageStatus
    known_at: datetime
    attempt: int = 1
    input_artifact_ids: tuple[str, ...] = ()
    output_artifact_ids: tuple[str, ...] = ()
    detail: Mapping[str, JsonValue] = field(default_factory=dict)
    run_id: str = field(init=False)
    status_record_id: str = field(init=False)
    content_hash: str = field(init=False)

    schema_version = CONTRACT_VERSION
    record_type = "stage_status"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _require_text(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "case_id", _require_text(self.case_id, "case_id"))
        object.__setattr__(self, "stage_id", _require_text(self.stage_id, "stage_id"))
        object.__setattr__(self, "manifest_hash", _require_text(self.manifest_hash, "manifest_hash"))
        object.__setattr__(self, "run_key", _require_text(self.run_key, "run_key"))
        try:
            object.__setattr__(self, "status", StageStatus(self.status))
        except ValueError as exc:
            raise ContractValidationError(f"unknown stage status: {self.status}") from exc
        object.__setattr__(self, "known_at", _normalise_time(self.known_at, "known_at"))
        if not isinstance(self.attempt, int) or isinstance(self.attempt, bool) or self.attempt < 1:
            raise ContractValidationError("attempt must be an integer of at least 1")
        object.__setattr__(self, "input_artifact_ids", _normalise_ids(self.input_artifact_ids, "input_artifact_ids"))
        object.__setattr__(self, "output_artifact_ids", _normalise_ids(self.output_artifact_ids, "output_artifact_ids"))
        object.__setattr__(self, "detail", _freeze_mapping(self.detail, "detail"))
        run_document = {
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "stage_id": self.stage_id,
            "manifest_hash": self.manifest_hash,
            "run_key": self.run_key,
            "attempt": self.attempt,
            "input_artifact_ids": list(self.input_artifact_ids),
        }
        object.__setattr__(self, "run_id", f"run1_{canonical_hash(run_document)}")
        digest = canonical_hash(self._content_document())
        object.__setattr__(self, "content_hash", digest)
        object.__setattr__(self, "status_record_id", f"ss1_{digest}")

    def _content_document(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "stage_id": self.stage_id,
            "manifest_hash": self.manifest_hash,
            "run_key": self.run_key,
            "run_id": self.run_id,
            "status": self.status.value,
            "known_at": _time_text(self.known_at),
            "attempt": self.attempt,
            "input_artifact_ids": list(self.input_artifact_ids),
            "output_artifact_ids": list(self.output_artifact_ids),
            "detail": _thaw_json(self.detail),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._content_document(),
            "status_record_id": self.status_record_id,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> StageStatusRecord:
        record = cls(
            tenant_id=raw["tenant_id"],
            case_id=raw["case_id"],
            stage_id=raw["stage_id"],
            manifest_hash=raw["manifest_hash"],
            run_key=raw["run_key"],
            status=raw["status"],
            known_at=_parse_time(raw["known_at"], "known_at"),
            attempt=raw.get("attempt", 1),
            input_artifact_ids=tuple(raw.get("input_artifact_ids", ())),
            output_artifact_ids=tuple(raw.get("output_artifact_ids", ())),
            detail=raw.get("detail", {}),
        )
        _verify_serialized(record, raw, "status_record_id")
        supplied_run_id = raw.get("run_id")
        if supplied_run_id is None:
            raise ContractValidationError("persisted stage status is missing run_id")
        if supplied_run_id != record.run_id:
            raise ContractValidationError("run_id does not match stage status content")
        return record

    def __hash__(self) -> int:
        return hash(self.status_record_id)


@dataclass(frozen=True, slots=True)
class StageInvocation:
    """Pre-execution identity of a stage and its immutable inputs.

    Output payload and output lineage are intentionally absent. A divergent
    output therefore cannot obtain a fresh replay identity by changing which
    evidence or assertions it claims to have produced.
    """

    tenant_id: str
    case_id: str
    stage_id: str
    manifest_hash: str
    input_artifact_ids: tuple[str, ...] = ()
    input_evidence_ids: tuple[str, ...] = ()
    input_assertion_ids: tuple[str, ...] = ()
    invocation_id: str = field(init=False)
    replay_key: str = field(init=False)
    content_hash: str = field(init=False)

    schema_version = CONTRACT_VERSION
    record_type = "stage_invocation"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _require_text(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "case_id", _require_text(self.case_id, "case_id"))
        object.__setattr__(self, "stage_id", _require_text(self.stage_id, "stage_id"))
        object.__setattr__(self, "manifest_hash", _require_text(self.manifest_hash, "manifest_hash"))
        object.__setattr__(self, "input_artifact_ids", _normalise_ids(self.input_artifact_ids, "input_artifact_ids"))
        object.__setattr__(self, "input_evidence_ids", _normalise_ids(self.input_evidence_ids, "input_evidence_ids"))
        object.__setattr__(
            self,
            "input_assertion_ids",
            _normalise_ids(self.input_assertion_ids, "input_assertion_ids"),
        )
        if not (self.input_artifact_ids or self.input_evidence_ids or self.input_assertion_ids):
            raise ContractValidationError("stage invocation must declare at least one immutable input")
        digest = canonical_hash(self._content_document())
        object.__setattr__(self, "content_hash", digest)
        object.__setattr__(self, "invocation_id", f"inv1_{digest}")
        object.__setattr__(self, "replay_key", f"replay1_{digest}")

    @classmethod
    def create(
        cls,
        manifest: StageManifest,
        *,
        tenant_id: str,
        case_id: str,
        input_artifact_ids: tuple[str, ...] = (),
        input_evidence_ids: tuple[str, ...] = (),
        input_assertion_ids: tuple[str, ...] = (),
    ) -> StageInvocation:
        return cls(
            tenant_id=tenant_id,
            case_id=case_id,
            stage_id=manifest.stage_id,
            manifest_hash=manifest.manifest_hash,
            input_artifact_ids=input_artifact_ids,
            input_evidence_ids=input_evidence_ids,
            input_assertion_ids=input_assertion_ids,
        )

    def _content_document(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "stage_id": self.stage_id,
            "manifest_hash": self.manifest_hash,
            "input_artifact_ids": list(self.input_artifact_ids),
            "input_evidence_ids": list(self.input_evidence_ids),
            "input_assertion_ids": list(self.input_assertion_ids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._content_document(),
            "invocation_id": self.invocation_id,
            "replay_key": self.replay_key,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> StageInvocation:
        record = cls(
            tenant_id=raw["tenant_id"],
            case_id=raw["case_id"],
            stage_id=raw["stage_id"],
            manifest_hash=raw["manifest_hash"],
            input_artifact_ids=tuple(raw.get("input_artifact_ids", ())),
            input_evidence_ids=tuple(raw.get("input_evidence_ids", ())),
            input_assertion_ids=tuple(raw.get("input_assertion_ids", ())),
        )
        _verify_serialized(record, raw, "invocation_id")
        supplied_replay_key = raw.get("replay_key")
        if supplied_replay_key is None:
            raise ContractValidationError("persisted stage invocation is missing replay_key")
        if supplied_replay_key != record.replay_key:
            raise ContractValidationError("replay_key does not match stage invocation content")
        return record

    def __hash__(self) -> int:
        return hash(self.invocation_id)


def derive_replay_key(manifest: StageManifest, invocation: StageInvocation) -> str:
    """Validate and return a replay key fixed before stage execution."""

    if invocation.stage_id != manifest.stage_id or invocation.manifest_hash != manifest.manifest_hash:
        raise ContractValidationError("stage invocation does not match manifest")
    return invocation.replay_key


@dataclass(frozen=True, slots=True)
class ArtifactReceipt:
    """Content-addressed acknowledgement of one output slot for one replay."""

    tenant_id: str
    case_id: str
    stage_id: str
    manifest_hash: str
    invocation_id: str
    replay_key: str
    output_slot: str
    artifact_type: str
    artifact_id: str
    artifact_hash: str
    known_at: datetime
    receipt_id: str = field(init=False)
    content_hash: str = field(init=False)

    schema_version = CONTRACT_VERSION
    record_type = "artifact_receipt"

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "case_id",
            "stage_id",
            "manifest_hash",
            "invocation_id",
            "replay_key",
            "output_slot",
            "artifact_type",
            "artifact_id",
            "artifact_hash",
        ):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        if not self.invocation_id.startswith("inv1_") or self.replay_key != "replay1_" + self.invocation_id[5:]:
            raise ContractValidationError("invocation_id and replay_key do not identify the same invocation")
        object.__setattr__(self, "known_at", _normalise_time(self.known_at, "known_at"))
        logical_document = {
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "stage_id": self.stage_id,
            "manifest_hash": self.manifest_hash,
            "invocation_id": self.invocation_id,
            "replay_key": self.replay_key,
            "output_slot": self.output_slot,
        }
        object.__setattr__(self, "receipt_id", f"rc1_{canonical_hash(logical_document)}")
        object.__setattr__(self, "content_hash", canonical_hash(self._content_document()))

    @classmethod
    def issue(
        cls,
        manifest: StageManifest,
        invocation: StageInvocation,
        artifact: StageArtifact,
        *,
        output_slot: str | None = None,
    ) -> ArtifactReceipt:
        if artifact.stage_id != manifest.stage_id:
            raise ContractValidationError("artifact stage_id does not match manifest")
        derive_replay_key(manifest, invocation)
        if artifact.tenant_id != invocation.tenant_id or artifact.case_id != invocation.case_id:
            raise ContractValidationError("artifact tenant/case scope does not match stage invocation")
        if artifact.input_artifact_ids != invocation.input_artifact_ids:
            raise ContractValidationError("artifact input_artifact_ids do not match stage invocation")
        if artifact.producer_version != manifest.stage_version:
            raise ContractValidationError("artifact producer_version does not match manifest")
        if artifact.artifact_type not in manifest.output_types:
            raise ContractValidationError("artifact_type is not declared by the manifest")
        return cls(
            tenant_id=artifact.tenant_id,
            case_id=artifact.case_id,
            stage_id=artifact.stage_id,
            manifest_hash=manifest.manifest_hash,
            invocation_id=invocation.invocation_id,
            replay_key=invocation.replay_key,
            output_slot=output_slot or artifact.artifact_type,
            artifact_type=artifact.artifact_type,
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact.content_hash,
            known_at=artifact.known_at,
        )

    def _content_document(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "stage_id": self.stage_id,
            "manifest_hash": self.manifest_hash,
            "invocation_id": self.invocation_id,
            "replay_key": self.replay_key,
            "output_slot": self.output_slot,
            "artifact_type": self.artifact_type,
            "artifact_id": self.artifact_id,
            "artifact_hash": self.artifact_hash,
            "known_at": _time_text(self.known_at),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content_document(), "receipt_id": self.receipt_id, "content_hash": self.content_hash}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> ArtifactReceipt:
        record = cls(
            tenant_id=raw["tenant_id"],
            case_id=raw["case_id"],
            stage_id=raw["stage_id"],
            manifest_hash=raw["manifest_hash"],
            invocation_id=raw["invocation_id"],
            replay_key=raw["replay_key"],
            output_slot=raw["output_slot"],
            artifact_type=raw["artifact_type"],
            artifact_id=raw["artifact_id"],
            artifact_hash=raw["artifact_hash"],
            known_at=_parse_time(raw["known_at"], "known_at"),
        )
        _verify_serialized(record, raw, "receipt_id")
        return record

    def __hash__(self) -> int:
        return hash(self.receipt_id)


class ReceiptBook:
    """Small in-memory idempotency primitive; persistence can implement the same rules."""

    def __init__(self, tenant_id: str, case_id: str) -> None:
        self.tenant_id = _require_text(tenant_id, "tenant_id")
        self.case_id = _require_text(case_id, "case_id")
        self._receipts: dict[str, ArtifactReceipt] = {}

    def record(self, receipt: ArtifactReceipt) -> ArtifactReceipt:
        if receipt.tenant_id != self.tenant_id or receipt.case_id != self.case_id:
            raise ReceiptConflictError("receipt is outside this tenant/case scope")
        existing = self._receipts.get(receipt.receipt_id)
        if existing is None:
            self._receipts[receipt.receipt_id] = receipt
            return receipt
        if (
            existing.artifact_id != receipt.artifact_id
            or existing.artifact_hash != receipt.artifact_hash
            or existing.artifact_type != receipt.artifact_type
        ):
            raise ReceiptConflictError(
                "replay output conflict: the stage/output slot already has a different artifact"
            )
        return existing

    def receipts(self) -> tuple[ArtifactReceipt, ...]:
        return tuple(self._receipts[key] for key in sorted(self._receipts))

    def __len__(self) -> int:
        return len(self._receipts)


@dataclass(frozen=True, slots=True)
class AssessmentDAG:
    """Validated immutable assessment topology with deterministic scheduling."""

    tenant_id: str
    case_id: str
    manifests: tuple[StageManifest, ...]
    dag_id: str = field(init=False)
    _by_id: Mapping[str, StageManifest] = field(init=False, repr=False, compare=False)
    _topological_order: tuple[str, ...] = field(init=False, repr=False, compare=False)

    schema_version = CONTRACT_VERSION
    record_type = "assessment_dag"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _require_text(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "case_id", _require_text(self.case_id, "case_id"))
        manifests = tuple(self.manifests)
        if not manifests:
            raise DAGValidationError("assessment DAG must contain at least one stage")
        if any(not isinstance(manifest, StageManifest) for manifest in manifests):
            raise DAGValidationError("manifests must contain only StageManifest records")
        by_id: dict[str, StageManifest] = {}
        for manifest in manifests:
            if manifest.stage_id in by_id:
                raise DAGValidationError(f"duplicate stage_id: {manifest.stage_id}")
            by_id[manifest.stage_id] = manifest
        missing = sorted(
            {dependency for manifest in manifests for dependency in manifest.depends_on if dependency not in by_id}
        )
        if missing:
            raise DAGValidationError("missing stage dependencies: " + ", ".join(missing))
        order = _topological_order(by_id)
        ordered_manifests = tuple(by_id[stage_id] for stage_id in order)
        object.__setattr__(self, "manifests", ordered_manifests)
        object.__setattr__(self, "_by_id", MappingProxyType(by_id))
        object.__setattr__(self, "_topological_order", order)
        digest = canonical_hash(
            {
                "schema_version": self.schema_version,
                "tenant_id": self.tenant_id,
                "case_id": self.case_id,
                "manifests": [by_id[stage_id].manifest_hash for stage_id in sorted(by_id)],
            }
        )
        object.__setattr__(self, "dag_id", f"dag1_{digest}")

    @property
    def topological_order(self) -> tuple[str, ...]:
        return self._topological_order

    def manifest(self, stage_id: str) -> StageManifest:
        try:
            return self._by_id[stage_id]
        except KeyError as exc:
            raise DAGValidationError(f"unknown stage_id: {stage_id}") from exc

    def ready_stages(
        self,
        statuses: Mapping[str, StageStatus | StageStatusRecord | str] | None = None,
        *,
        retry_failed: bool = False,
        limit: int | None = None,
    ) -> tuple[StageManifest, ...]:
        if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 1):
            raise DAGValidationError("limit must be a positive integer")
        states = self._validate_statuses(statuses or {})
        ready: list[StageManifest] = []
        for stage_id in self._topological_order:
            current = states.get(stage_id, StageStatus.PENDING)
            eligible = current is StageStatus.PENDING or (retry_failed and current is StageStatus.FAILED)
            if not eligible:
                continue
            manifest = self._by_id[stage_id]
            if all(states.get(dependency) is StageStatus.SUCCEEDED for dependency in manifest.depends_on):
                ready.append(manifest)
                if limit is not None and len(ready) >= limit:
                    break
        return tuple(ready)

    def ready_from_receipts(self, receipts: Iterable[ArtifactReceipt]) -> tuple[StageManifest, ...]:
        output_types: dict[str, set[str]] = {}
        for receipt in receipts:
            if receipt.tenant_id != self.tenant_id or receipt.case_id != self.case_id:
                raise DAGValidationError("receipt is outside this DAG tenant/case scope")
            manifest = self._by_id.get(receipt.stage_id)
            if manifest is None:
                raise DAGValidationError(f"receipt references unknown stage_id: {receipt.stage_id}")
            if receipt.manifest_hash != manifest.manifest_hash:
                raise DAGValidationError(f"receipt manifest mismatch for stage: {receipt.stage_id}")
            output_types.setdefault(receipt.stage_id, set()).add(receipt.artifact_type)
        states: dict[str, StageStatus] = {}
        for stage_id, produced in output_types.items():
            if set(self._by_id[stage_id].output_types).issubset(produced):
                states[stage_id] = StageStatus.SUCCEEDED
        return self.ready_stages(states)

    def _validate_statuses(
        self, statuses: Mapping[str, StageStatus | StageStatusRecord | str]
    ) -> dict[str, StageStatus]:
        unknown = sorted(set(statuses) - set(self._by_id))
        if unknown:
            raise DAGValidationError("statuses reference unknown stages: " + ", ".join(unknown))
        states: dict[str, StageStatus] = {}
        for stage_id, value in statuses.items():
            if isinstance(value, StageStatusRecord):
                if value.stage_id != stage_id:
                    raise DAGValidationError(f"status key does not match record stage_id: {stage_id}")
                if value.tenant_id != self.tenant_id or value.case_id != self.case_id:
                    raise DAGValidationError(f"status is outside this DAG tenant/case scope: {stage_id}")
                if value.manifest_hash != self._by_id[stage_id].manifest_hash:
                    raise DAGValidationError(f"status manifest mismatch for stage: {stage_id}")
                states[stage_id] = value.status
                continue
            try:
                states[stage_id] = StageStatus(value)
            except ValueError as exc:
                raise DAGValidationError(f"unknown status for stage {stage_id}: {value}") from exc
        return states

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "dag_id": self.dag_id,
            "topological_order": list(self.topological_order),
            "manifests": [manifest.to_dict() for manifest in self.manifests],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> AssessmentDAG:
        if raw.get("schema_version") != CONTRACT_VERSION:
            raise ContractValidationError("unsupported schema_version")
        if raw.get("record_type") != cls.record_type:
            raise ContractValidationError("record_type does not match assessment DAG")
        dag = cls(
            tenant_id=raw["tenant_id"],
            case_id=raw["case_id"],
            manifests=tuple(StageManifest.from_dict(item) for item in raw.get("manifests", ())),
        )
        supplied_id = raw.get("dag_id")
        if supplied_id is None:
            raise ContractValidationError("persisted assessment DAG is missing dag_id")
        if supplied_id != dag.dag_id:
            raise ContractValidationError("dag_id does not match assessment DAG content")
        supplied_order = raw.get("topological_order")
        if supplied_order is None:
            raise ContractValidationError("persisted assessment DAG is missing topological_order")
        if tuple(supplied_order) != dag.topological_order:
            raise ContractValidationError("topological_order does not match assessment DAG content")
        return dag


def _topological_order(by_id: Mapping[str, StageManifest]) -> tuple[str, ...]:
    indegree = {stage_id: len(manifest.depends_on) for stage_id, manifest in by_id.items()}
    dependants: dict[str, list[str]] = {stage_id: [] for stage_id in by_id}
    for stage_id, manifest in by_id.items():
        for dependency in manifest.depends_on:
            dependants[dependency].append(stage_id)
    ready = sorted(stage_id for stage_id, degree in indegree.items() if degree == 0)
    result: list[str] = []
    while ready:
        stage_id = ready.pop(0)
        result.append(stage_id)
        for dependant in sorted(dependants[stage_id]):
            indegree[dependant] -= 1
            if indegree[dependant] == 0:
                ready.append(dependant)
                ready.sort()
    if len(result) != len(by_id):
        cycle = _find_cycle(by_id)
        suffix = " -> ".join(cycle) if cycle else "unknown"
        raise DAGValidationError(f"assessment DAG contains a cycle: {suffix}")
    return tuple(result)


def _find_cycle(by_id: Mapping[str, StageManifest]) -> tuple[str, ...]:
    visited: set[str] = set()
    active: list[str] = []
    active_set: set[str] = set()

    def visit(stage_id: str) -> tuple[str, ...]:
        if stage_id in active_set:
            start = active.index(stage_id)
            return tuple(active[start:] + [stage_id])
        if stage_id in visited:
            return ()
        visited.add(stage_id)
        active.append(stage_id)
        active_set.add(stage_id)
        for dependency in by_id[stage_id].depends_on:
            cycle = visit(dependency)
            if cycle:
                return cycle
        active.pop()
        active_set.remove(stage_id)
        return ()

    for candidate in sorted(by_id):
        cycle = visit(candidate)
        if cycle:
            return cycle
    return ()


__all__ = [
    "ArtifactReceipt",
    "AssessmentDAG",
    "DAGValidationError",
    "ReceiptBook",
    "ReceiptConflictError",
    "StageManifest",
    "StageInvocation",
    "StageStatus",
    "StageStatusRecord",
    "derive_replay_key",
]
