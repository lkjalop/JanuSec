"""Immutable typed-graph projection receipts and freshness evaluation."""

from __future__ import annotations

import datetime as dt
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .records import canonical_hash

GRAPH_PROJECTION_VERSION = "janusec.typed-case-graph/v1"
NORMALIZER_VERSION = "janusec.directionality/v3"
MAPPING_VERSION = "ocsf-semantic-map/v2"
_GRAPH_INPUT_RECORD_TYPES = frozenset({
    "evidence", "assertion", "stage_artifact", "artifact_receipt", "assessment_dag"
})


class StalenessReason(str, Enum):
    LEDGER_ADVANCED = "ledger_advanced"
    NORMALIZER_CHANGED = "normalizer_changed"
    MAPPING_CHANGED = "mapping_changed"
    SENSOR_WATERMARK_EXPIRED = "sensor_watermark_expired"
    TOPOLOGY_EXPIRED = "topology_expired"
    IAM_CHANGED = "iam_changed"
    TOPOLOGY_CHANGED = "topology_changed"
    CMDB_CHANGED = "cmdb_changed"
    CLOCK_CALIBRATION_CHANGED = "clock_calibration_changed"


@dataclass(frozen=True, slots=True)
class GraphProjectionReceipt:
    tenant_id: str
    case_id: str
    projection_id: str
    ledger_head_hash: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    normalizer_version: str
    mapping_version: str
    built_at: str
    source_watermarks: dict[str, str] = field(default_factory=dict)
    topology_valid_to: str | None = None
    clock_calibration_hash: str | None = None
    iam_receipt_hash: str | None = None
    topology_receipt_hash: str | None = None
    cmdb_receipt_hash: str | None = None
    receipt_id: str = field(init=False)
    content_hash: str = field(init=False)

    record_type = "graph_view_receipt"
    schema_version = "janusec.graph-view-receipt/v1"

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.case_id, self.projection_id, self.ledger_head_hash)):
            raise ValueError("graph_receipt_requires_scope_projection_and_ledger_head")
        digest = canonical_hash(self._content())
        object.__setattr__(self, "content_hash", digest)
        object.__setattr__(self, "receipt_id", f"gvr_{digest}")

    def _content(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "projection_id": self.projection_id,
            "ledger_head_hash": self.ledger_head_hash,
            "node_ids": sorted(self.node_ids),
            "edge_ids": sorted(self.edge_ids),
            "normalizer_version": self.normalizer_version,
            "mapping_version": self.mapping_version,
            "built_at": self.built_at,
            "source_watermarks": dict(sorted(self.source_watermarks.items())),
            "topology_valid_to": self.topology_valid_to,
            "clock_calibration_hash": self.clock_calibration_hash,
            "iam_receipt_hash": self.iam_receipt_hash,
            "topology_receipt_hash": self.topology_receipt_hash,
            "cmdb_receipt_hash": self.cmdb_receipt_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content(), "receipt_id": self.receipt_id, "content_hash": self.content_hash}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "GraphProjectionReceipt":
        return cls(
            tenant_id=str(raw.get("tenant_id") or ""),
            case_id=str(raw.get("case_id") or ""),
            projection_id=str(raw.get("projection_id") or ""),
            ledger_head_hash=str(raw.get("ledger_head_hash") or ""),
            node_ids=tuple(str(value) for value in raw.get("node_ids") or ()),
            edge_ids=tuple(str(value) for value in raw.get("edge_ids") or ()),
            normalizer_version=str(raw.get("normalizer_version") or ""),
            mapping_version=str(raw.get("mapping_version") or ""),
            built_at=str(raw.get("built_at") or ""),
            source_watermarks={str(k): str(v) for k, v in (raw.get("source_watermarks") or {}).items()},
            topology_valid_to=raw.get("topology_valid_to"),
            clock_calibration_hash=raw.get("clock_calibration_hash"),
            iam_receipt_hash=raw.get("iam_receipt_hash"),
            topology_receipt_hash=raw.get("topology_receipt_hash"),
            cmdb_receipt_hash=raw.get("cmdb_receipt_hash"),
        )


def _time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def projection_staleness(
    receipt: GraphProjectionReceipt,
    *,
    current_ledger_head_hash: str,
    normalizer_version: str,
    mapping_version: str,
    now: dt.datetime | None = None,
    sensor_max_age_seconds: dict[str, int] | None = None,
    clock_calibration_hash: str | None = None,
    iam_receipt_hash: str | None = None,
    topology_receipt_hash: str | None = None,
    cmdb_receipt_hash: str | None = None,
) -> tuple[StalenessReason, ...]:
    """Explain why a projection must be rebuilt; never mutate the old receipt."""

    reasons: list[StalenessReason] = []
    if receipt.ledger_head_hash != current_ledger_head_hash:
        reasons.append(StalenessReason.LEDGER_ADVANCED)
    if receipt.normalizer_version != normalizer_version:
        reasons.append(StalenessReason.NORMALIZER_CHANGED)
    if receipt.mapping_version != mapping_version:
        reasons.append(StalenessReason.MAPPING_CHANGED)
    if clock_calibration_hash is not None and receipt.clock_calibration_hash != clock_calibration_hash:
        reasons.append(StalenessReason.CLOCK_CALIBRATION_CHANGED)
    if iam_receipt_hash is not None and receipt.iam_receipt_hash != iam_receipt_hash:
        reasons.append(StalenessReason.IAM_CHANGED)
    if topology_receipt_hash is not None and receipt.topology_receipt_hash != topology_receipt_hash:
        reasons.append(StalenessReason.TOPOLOGY_CHANGED)
    if cmdb_receipt_hash is not None and receipt.cmdb_receipt_hash != cmdb_receipt_hash:
        reasons.append(StalenessReason.CMDB_CHANGED)
    now = now or dt.datetime.now(dt.timezone.utc)
    if receipt.topology_valid_to and (_time(receipt.topology_valid_to) or now) <= now:
        reasons.append(StalenessReason.TOPOLOGY_EXPIRED)
    for source, max_age in (sensor_max_age_seconds or {}).items():
        watermark = _time(receipt.source_watermarks.get(source))
        if watermark is None or (now - watermark).total_seconds() > max(0, max_age):
            reasons.append(StalenessReason.SENSOR_WATERMARK_EXPIRED)
            break
    return tuple(reasons)


def eligible_ledger_head(records: list[dict[str, Any]]) -> str:
    """Hash only graph inputs so later reports/model runs do not stale the graph."""

    inputs = [
        {"record_type": record.get("record_type"), "content_hash": record.get("content_hash")}
        for record in records
        if record.get("record_type") in _GRAPH_INPUT_RECORD_TYPES and record.get("content_hash")
    ]
    return canonical_hash(inputs)


def configured_sensor_slas() -> dict[str, int]:
    """Read optional per-source freshness SLAs for live assessment projections."""

    raw = os.getenv("GRAPH_SENSOR_MAX_AGE_SECONDS_JSON", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {
        str(source): int(seconds)
        for source, seconds in parsed.items()
        if str(source).strip() and isinstance(seconds, (int, float)) and int(seconds) >= 0
    }


__all__ = [
    "GRAPH_PROJECTION_VERSION", "MAPPING_VERSION", "NORMALIZER_VERSION",
    "GraphProjectionReceipt", "StalenessReason", "configured_sensor_slas", "eligible_ledger_head",
    "projection_staleness",
]
