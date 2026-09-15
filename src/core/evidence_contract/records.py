"""Immutable Evidence Contract v1 records.

The contract is intentionally independent of persistence and transport layers.  It
provides JSON-safe, content-addressed records that can be serialized, replayed, and
verified without importing the API, graph, ingest, or LLM stacks.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, ClassVar, TypeAlias

CONTRACT_VERSION = "janusec.evidence-contract/v1"

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | Mapping[str, "JsonValue"] | tuple["JsonValue", ...] | list["JsonValue"]
FrozenJsonValue: TypeAlias = JsonScalar | Mapping[str, "FrozenJsonValue"] | tuple["FrozenJsonValue", ...]


class ContractValidationError(ValueError):
    """Raised when a record cannot satisfy Evidence Contract v1."""


class AssertionType(str, Enum):
    """Permitted epistemic classes for an assertion.

    The value is deliberately part of the assertion hash so simulated or
    predicted material cannot be relabelled as observed without creating a new
    assertion.
    """

    OBSERVED = "observed"
    CONFIGURED = "configured"
    RESOLVED = "resolved"
    INFERRED = "inferred"
    SIMULATED = "simulated"
    PREDICTED = "predicted"


def _require_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractValidationError(f"{name} must be a non-empty string")
    return value.strip()


def _normalise_time(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime):
        raise ContractValidationError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ContractValidationError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _time_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_time(value: Any, name: str) -> datetime:
    if isinstance(value, datetime):
        return _normalise_time(value, name)
    if not isinstance(value, str):
        raise ContractValidationError(f"{name} must be an RFC3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractValidationError(f"{name} must be an RFC3339 string") from exc
    return _normalise_time(parsed, name)


def _freeze_json(value: Any, path: str = "payload") -> FrozenJsonValue:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractValidationError(f"{path} contains a non-finite float")
        return value
    if isinstance(value, Mapping):
        keys = list(value.keys())
        if any(not isinstance(key, str) for key in keys):
            raise ContractValidationError(f"{path} object keys must be strings")
        return MappingProxyType(
            {key: _freeze_json(value[key], f"{path}.{key}") for key in sorted(keys)}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item, f"{path}[{index}]") for index, item in enumerate(value))
    raise ContractValidationError(f"{path} contains unsupported value type {type(value).__name__}")


def _freeze_mapping(value: Mapping[str, JsonValue] | None, name: str) -> Mapping[str, FrozenJsonValue]:
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        raise ContractValidationError(f"{name} must be an object")
    frozen = _freeze_json(value, name)
    assert isinstance(frozen, Mapping)
    return frozen


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    """Return the canonical JSON representation used by all v1 hashes."""

    frozen = _freeze_json(value, "document")
    return json.dumps(
        _thaw_json(frozen),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_hash(value: Any) -> str:
    """Return a lowercase SHA-256 digest of canonical JSON."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _normalise_ids(values: Any, name: str) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        raise ContractValidationError(f"{name} must be a sequence of identifiers")
    try:
        normalised = {_require_text(value, name) for value in values}
    except TypeError as exc:
        raise ContractValidationError(f"{name} must be a sequence of identifiers") from exc
    return tuple(sorted(normalised))


def _validate_interval(valid_from: datetime, valid_to: datetime | None) -> None:
    if valid_to is not None and valid_to < valid_from:
        raise ContractValidationError("valid_to must be at or after valid_from")


def _normalise_sha256(value: str, name: str) -> str:
    digest = _require_text(value, name).lower()
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ContractValidationError(f"{name} must be a 64-character SHA-256 digest")
    return digest


def _normalise_offset(value: int | None) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractValidationError("raw_offset must be a non-negative integer or null")
    return value


def _normalise_finite_number(
    value: float,
    name: str,
    *,
    non_negative: bool = False,
) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ContractValidationError(f"{name} must be a finite number") from exc
    if not math.isfinite(number):
        raise ContractValidationError(f"{name} must be a finite number")
    if non_negative and number < 0:
        raise ContractValidationError(f"{name} must be non-negative")
    return number


def _verify_serialized(record: Any, raw: Mapping[str, Any], id_field: str) -> None:
    if raw.get("schema_version") != CONTRACT_VERSION:
        raise ContractValidationError("unsupported schema_version")
    if raw.get("record_type") != record.record_type:
        raise ContractValidationError("record_type does not match record content")
    supplied_hash = raw.get("content_hash")
    if supplied_hash is None:
        raise ContractValidationError("persisted record is missing content_hash")
    if supplied_hash != record.content_hash:
        raise ContractValidationError("content_hash does not match record content")
    supplied_id = raw.get(id_field)
    if supplied_id is None:
        raise ContractValidationError(f"persisted record is missing {id_field}")
    if supplied_id != getattr(record, id_field):
        raise ContractValidationError(f"{id_field} does not match record content")


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """An immutable, audit-grade source record with explicit provenance.

    ``occurred_at`` is valid/event time. ``known_at`` is knowledge/transaction
    time. ``observed_at`` and ``ingested_at`` preserve the collection path rather
    than collapsing delayed evidence into one timestamp.
    """

    tenant_id: str
    case_id: str
    evidence_type: str
    source: str
    source_native_id: str
    raw_locator: str
    raw_sha256: str
    occurred_at: datetime
    observed_at: datetime
    ingested_at: datetime
    known_at: datetime
    collector_version: str
    parser_version: str
    mapping_version: str
    source_schema_version: str
    clock_source: str
    source_timezone: str
    clock_skew_seconds: float
    time_uncertainty_seconds: float
    acl: tuple[str, ...]
    retention_policy: str
    classification: str
    legal_hold: bool
    payload: Mapping[str, JsonValue]
    raw_offset: int | None = None
    valid_to: datetime | None = None
    evidence_id: str = field(init=False)
    content_hash: str = field(init=False)

    schema_version: ClassVar[str] = CONTRACT_VERSION
    record_type: ClassVar[str] = "evidence"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _require_text(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "case_id", _require_text(self.case_id, "case_id"))
        object.__setattr__(self, "evidence_type", _require_text(self.evidence_type, "evidence_type"))
        object.__setattr__(self, "source", _require_text(self.source, "source"))
        object.__setattr__(self, "source_native_id", _require_text(self.source_native_id, "source_native_id"))
        object.__setattr__(self, "raw_locator", _require_text(self.raw_locator, "raw_locator"))
        object.__setattr__(self, "raw_sha256", _normalise_sha256(self.raw_sha256, "raw_sha256"))
        object.__setattr__(self, "raw_offset", _normalise_offset(self.raw_offset))
        object.__setattr__(self, "occurred_at", _normalise_time(self.occurred_at, "occurred_at"))
        object.__setattr__(self, "observed_at", _normalise_time(self.observed_at, "observed_at"))
        object.__setattr__(self, "ingested_at", _normalise_time(self.ingested_at, "ingested_at"))
        object.__setattr__(self, "known_at", _normalise_time(self.known_at, "known_at"))
        if self.known_at < self.ingested_at:
            raise ContractValidationError("known_at must be at or after ingested_at")
        for name in ("collector_version", "parser_version", "mapping_version", "source_schema_version"):
            object.__setattr__(self, name, _require_text(getattr(self, name), name))
        object.__setattr__(self, "clock_source", _require_text(self.clock_source, "clock_source"))
        object.__setattr__(self, "source_timezone", _require_text(self.source_timezone, "source_timezone"))
        object.__setattr__(
            self,
            "clock_skew_seconds",
            _normalise_finite_number(self.clock_skew_seconds, "clock_skew_seconds"),
        )
        object.__setattr__(
            self,
            "time_uncertainty_seconds",
            _normalise_finite_number(
                self.time_uncertainty_seconds,
                "time_uncertainty_seconds",
                non_negative=True,
            ),
        )
        object.__setattr__(self, "acl", _normalise_ids(self.acl, "acl"))
        if not self.acl:
            raise ContractValidationError("acl must contain at least one principal or policy")
        object.__setattr__(
            self,
            "retention_policy",
            _require_text(self.retention_policy, "retention_policy"),
        )
        object.__setattr__(
            self,
            "classification",
            _require_text(self.classification, "classification"),
        )
        if not isinstance(self.legal_hold, bool):
            raise ContractValidationError("legal_hold must be a boolean")
        if self.valid_to is not None:
            object.__setattr__(self, "valid_to", _normalise_time(self.valid_to, "valid_to"))
        _validate_interval(self.occurred_at, self.valid_to)
        object.__setattr__(self, "payload", _freeze_mapping(self.payload, "payload"))
        digest = canonical_hash(self._content_document())
        object.__setattr__(self, "content_hash", digest)
        object.__setattr__(self, "evidence_id", f"ev1_{digest}")

    def _content_document(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "evidence_type": self.evidence_type,
            "source": self.source,
            "source_native_id": self.source_native_id,
            "raw_locator": self.raw_locator,
            "raw_sha256": self.raw_sha256,
            "raw_offset": self.raw_offset,
            "occurred_at": _time_text(self.occurred_at),
            "observed_at": _time_text(self.observed_at),
            "ingested_at": _time_text(self.ingested_at),
            "valid_to": _time_text(self.valid_to) if self.valid_to else None,
            "known_at": _time_text(self.known_at),
            "collector_version": self.collector_version,
            "parser_version": self.parser_version,
            "mapping_version": self.mapping_version,
            "source_schema_version": self.source_schema_version,
            "clock_source": self.clock_source,
            "source_timezone": self.source_timezone,
            "clock_skew_seconds": self.clock_skew_seconds,
            "time_uncertainty_seconds": self.time_uncertainty_seconds,
            "acl": list(self.acl),
            "retention_policy": self.retention_policy,
            "classification": self.classification,
            "legal_hold": self.legal_hold,
            "payload": _thaw_json(self.payload),
        }

    @property
    def valid_from(self) -> datetime:
        """Backward-readable alias for the event/valid timestamp."""

        return self.occurred_at

    def to_dict(self) -> dict[str, Any]:
        return {**self._content_document(), "evidence_id": self.evidence_id, "content_hash": self.content_hash}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> EvidenceRecord:
        record = cls(
            tenant_id=raw["tenant_id"],
            case_id=raw["case_id"],
            evidence_type=raw["evidence_type"],
            source=raw["source"],
            source_native_id=raw["source_native_id"],
            raw_locator=raw["raw_locator"],
            raw_sha256=raw["raw_sha256"],
            raw_offset=raw.get("raw_offset"),
            occurred_at=_parse_time(raw.get("occurred_at", raw.get("valid_from")), "occurred_at"),
            observed_at=_parse_time(raw["observed_at"], "observed_at"),
            ingested_at=_parse_time(raw["ingested_at"], "ingested_at"),
            valid_to=_parse_time(raw["valid_to"], "valid_to") if raw.get("valid_to") else None,
            known_at=_parse_time(raw["known_at"], "known_at"),
            collector_version=raw["collector_version"],
            parser_version=raw["parser_version"],
            mapping_version=raw["mapping_version"],
            source_schema_version=raw["source_schema_version"],
            clock_source=raw["clock_source"],
            source_timezone=raw["source_timezone"],
            clock_skew_seconds=raw["clock_skew_seconds"],
            time_uncertainty_seconds=raw["time_uncertainty_seconds"],
            acl=tuple(raw.get("acl", ())),
            retention_policy=raw["retention_policy"],
            classification=raw["classification"],
            legal_hold=raw["legal_hold"],
            payload=raw.get("payload", {}),
        )
        _verify_serialized(record, raw, "evidence_id")
        return record

    def __hash__(self) -> int:
        return hash(self.evidence_id)


@dataclass(frozen=True, slots=True)
class AssertionRecord:
    """A typed assertion with explicit evidence support and bitemporal scope."""

    tenant_id: str
    case_id: str
    assertion_type: AssertionType
    subject: str
    predicate: str
    object_value: JsonValue
    valid_from: datetime
    known_at: datetime
    analyzer_id: str
    analyzer_version: str
    evidence_ids: tuple[str, ...] = ()
    contradicting_evidence_ids: tuple[str, ...] = ()
    supersedes_assertion_ids: tuple[str, ...] = ()
    confidence: float | None = None
    valid_to: datetime | None = None
    attributes: Mapping[str, JsonValue] = field(default_factory=dict)
    assertion_id: str = field(init=False)
    content_hash: str = field(init=False)

    schema_version: ClassVar[str] = CONTRACT_VERSION
    record_type: ClassVar[str] = "assertion"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _require_text(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "case_id", _require_text(self.case_id, "case_id"))
        try:
            object.__setattr__(self, "assertion_type", AssertionType(self.assertion_type))
        except ValueError as exc:
            allowed = ", ".join(item.value for item in AssertionType)
            raise ContractValidationError(f"assertion_type must be one of: {allowed}") from exc
        object.__setattr__(self, "subject", _require_text(self.subject, "subject"))
        object.__setattr__(self, "predicate", _require_text(self.predicate, "predicate"))
        object.__setattr__(self, "analyzer_id", _require_text(self.analyzer_id, "analyzer_id"))
        object.__setattr__(self, "analyzer_version", _require_text(self.analyzer_version, "analyzer_version"))
        object.__setattr__(self, "object_value", _freeze_json(self.object_value, "object_value"))
        object.__setattr__(self, "valid_from", _normalise_time(self.valid_from, "valid_from"))
        object.__setattr__(self, "known_at", _normalise_time(self.known_at, "known_at"))
        if self.valid_to is not None:
            object.__setattr__(self, "valid_to", _normalise_time(self.valid_to, "valid_to"))
        _validate_interval(self.valid_from, self.valid_to)
        object.__setattr__(self, "evidence_ids", _normalise_ids(self.evidence_ids, "evidence_ids"))
        object.__setattr__(
            self,
            "contradicting_evidence_ids",
            _normalise_ids(self.contradicting_evidence_ids, "contradicting_evidence_ids"),
        )
        object.__setattr__(
            self,
            "supersedes_assertion_ids",
            _normalise_ids(self.supersedes_assertion_ids, "supersedes_assertion_ids"),
        )
        overlap = set(self.evidence_ids).intersection(self.contradicting_evidence_ids)
        if overlap:
            raise ContractValidationError(
                "evidence cannot simultaneously support and contradict an assertion: " + ", ".join(sorted(overlap))
            )
        if self.confidence is not None:
            confidence = float(self.confidence)
            if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
                raise ContractValidationError("confidence must be between 0 and 1")
            object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "attributes", _freeze_mapping(self.attributes, "attributes"))
        digest = canonical_hash(self._content_document())
        object.__setattr__(self, "content_hash", digest)
        object.__setattr__(self, "assertion_id", f"as1_{digest}")

    def _content_document(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "assertion_type": self.assertion_type.value,
            "subject": self.subject,
            "predicate": self.predicate,
            "object_value": _thaw_json(self.object_value),
            "valid_from": _time_text(self.valid_from),
            "valid_to": _time_text(self.valid_to) if self.valid_to else None,
            "known_at": _time_text(self.known_at),
            "analyzer_id": self.analyzer_id,
            "analyzer_version": self.analyzer_version,
            "evidence_ids": list(self.evidence_ids),
            "contradicting_evidence_ids": list(self.contradicting_evidence_ids),
            "supersedes_assertion_ids": list(self.supersedes_assertion_ids),
            "confidence": self.confidence,
            "attributes": _thaw_json(self.attributes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content_document(), "assertion_id": self.assertion_id, "content_hash": self.content_hash}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> AssertionRecord:
        record = cls(
            tenant_id=raw["tenant_id"],
            case_id=raw["case_id"],
            assertion_type=raw["assertion_type"],
            subject=raw["subject"],
            predicate=raw["predicate"],
            object_value=raw.get("object_value"),
            valid_from=_parse_time(raw["valid_from"], "valid_from"),
            valid_to=_parse_time(raw["valid_to"], "valid_to") if raw.get("valid_to") else None,
            known_at=_parse_time(raw["known_at"], "known_at"),
            analyzer_id=raw["analyzer_id"],
            analyzer_version=raw["analyzer_version"],
            evidence_ids=tuple(raw.get("evidence_ids", ())),
            contradicting_evidence_ids=tuple(raw.get("contradicting_evidence_ids", ())),
            supersedes_assertion_ids=tuple(raw.get("supersedes_assertion_ids", ())),
            confidence=raw.get("confidence"),
            attributes=raw.get("attributes", {}),
        )
        _verify_serialized(record, raw, "assertion_id")
        return record

    def __hash__(self) -> int:
        return hash(self.assertion_id)


@dataclass(frozen=True, slots=True)
class StageArtifact:
    """Immutable output of one deterministic assessment stage.

    ``evidence_ids`` and ``assertion_ids`` describe output/citation lineage. They
    are deliberately not used as the pre-execution invocation identity; that is
    owned by :class:`StageInvocation` in the DAG module.
    """

    tenant_id: str
    case_id: str
    stage_id: str
    artifact_type: str
    producer_version: str
    valid_from: datetime
    known_at: datetime
    payload: Mapping[str, JsonValue]
    input_artifact_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    assertion_ids: tuple[str, ...] = ()
    valid_to: datetime | None = None
    artifact_id: str = field(init=False)
    content_hash: str = field(init=False)

    schema_version: ClassVar[str] = CONTRACT_VERSION
    record_type: ClassVar[str] = "stage_artifact"

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", _require_text(self.tenant_id, "tenant_id"))
        object.__setattr__(self, "case_id", _require_text(self.case_id, "case_id"))
        object.__setattr__(self, "stage_id", _require_text(self.stage_id, "stage_id"))
        object.__setattr__(self, "artifact_type", _require_text(self.artifact_type, "artifact_type"))
        object.__setattr__(self, "producer_version", _require_text(self.producer_version, "producer_version"))
        object.__setattr__(self, "valid_from", _normalise_time(self.valid_from, "valid_from"))
        object.__setattr__(self, "known_at", _normalise_time(self.known_at, "known_at"))
        if self.valid_to is not None:
            object.__setattr__(self, "valid_to", _normalise_time(self.valid_to, "valid_to"))
        _validate_interval(self.valid_from, self.valid_to)
        object.__setattr__(self, "payload", _freeze_mapping(self.payload, "payload"))
        object.__setattr__(self, "input_artifact_ids", _normalise_ids(self.input_artifact_ids, "input_artifact_ids"))
        object.__setattr__(self, "evidence_ids", _normalise_ids(self.evidence_ids, "evidence_ids"))
        object.__setattr__(self, "assertion_ids", _normalise_ids(self.assertion_ids, "assertion_ids"))
        digest = canonical_hash(self._content_document())
        object.__setattr__(self, "content_hash", digest)
        object.__setattr__(self, "artifact_id", f"sa1_{digest}")

    def _content_document(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "stage_id": self.stage_id,
            "artifact_type": self.artifact_type,
            "producer_version": self.producer_version,
            "valid_from": _time_text(self.valid_from),
            "valid_to": _time_text(self.valid_to) if self.valid_to else None,
            "known_at": _time_text(self.known_at),
            "input_artifact_ids": list(self.input_artifact_ids),
            "evidence_ids": list(self.evidence_ids),
            "assertion_ids": list(self.assertion_ids),
            "payload": _thaw_json(self.payload),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content_document(), "artifact_id": self.artifact_id, "content_hash": self.content_hash}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> StageArtifact:
        record = cls(
            tenant_id=raw["tenant_id"],
            case_id=raw["case_id"],
            stage_id=raw["stage_id"],
            artifact_type=raw["artifact_type"],
            producer_version=raw["producer_version"],
            valid_from=_parse_time(raw["valid_from"], "valid_from"),
            valid_to=_parse_time(raw["valid_to"], "valid_to") if raw.get("valid_to") else None,
            known_at=_parse_time(raw["known_at"], "known_at"),
            input_artifact_ids=tuple(raw.get("input_artifact_ids", ())),
            evidence_ids=tuple(raw.get("evidence_ids", ())),
            assertion_ids=tuple(raw.get("assertion_ids", ())),
            payload=raw.get("payload", {}),
        )
        _verify_serialized(record, raw, "artifact_id")
        return record

    def __hash__(self) -> int:
        return hash(self.artifact_id)


__all__ = [
    "AssertionRecord",
    "AssertionType",
    "CONTRACT_VERSION",
    "ContractValidationError",
    "EvidenceRecord",
    "FrozenJsonValue",
    "JsonValue",
    "StageArtifact",
    "canonical_hash",
    "canonical_json",
]
