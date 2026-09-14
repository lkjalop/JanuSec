"""Typed cross-stitching edges that preserve epistemic boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class EdgeType(str, Enum):
    OBSERVED_CAUSAL = "observed_causal"
    OBSERVED_INTERACTION = "observed_interaction"
    TEMPORAL_PRECEDES = "temporal_precedes"
    CONFIGURED_EXPOSURE = "configured_exposure"
    CANDIDATE_MATCH = "candidate_match"
    CTI_RELATION = "cti_relation"
    CLAIM_SUPPORT = "claim_support"
    CONTRADICTS = "contradicts"
    SUPERSEDES = "supersedes"


_WEAK_IDENTIFIERS = {"ip", "username", "hostname", "pid", "email_subject"}


@dataclass(frozen=True, slots=True)
class TypedEdge:
    source: str
    target: str
    edge_type: EdgeType
    evidence_ids: tuple[str, ...]
    match_basis: tuple[str, ...] = ()
    confidence: float | None = None
    source_ref: str | None = None
    target_ref: str | None = None
    time: dict[str, Any] | None = None
    observations: tuple[dict[str, Any], ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> TypedEdge:
        edge = cls(
            source=str(raw.get("source") or ""),
            target=str(raw.get("target") or ""),
            edge_type=EdgeType(raw.get("edge_type")),
            evidence_ids=tuple(str(value) for value in raw.get("evidence_ids") or ()),
            match_basis=tuple(str(value) for value in raw.get("match_basis") or ()),
            confidence=float(raw["confidence"]) if raw.get("confidence") is not None else None,
            source_ref=str(raw["source_ref"]) if raw.get("source_ref") is not None else None,
            target_ref=str(raw["target_ref"]) if raw.get("target_ref") is not None else None,
            time=dict(raw["time"]) if isinstance(raw.get("time"), dict) else None,
            observations=tuple(dict(item) for item in raw.get("observations") or [] if isinstance(item, dict)),
        )
        edge.validate()
        return edge

    def validate(self) -> None:
        if not self.source or not self.target or self.source == self.target:
            raise ValueError("typed_edge_requires_distinct_endpoints")
        if self.edge_type in {
            EdgeType.OBSERVED_CAUSAL,
            EdgeType.OBSERVED_INTERACTION,
            EdgeType.TEMPORAL_PRECEDES,
            EdgeType.CLAIM_SUPPORT,
            EdgeType.CONTRADICTS,
            EdgeType.SUPERSEDES,
        } and not self.evidence_ids:
            raise ValueError("causal_support_and_correction_edges_require_evidence")
        basis = {value.lower() for value in self.match_basis}
        if self.edge_type is not EdgeType.CANDIDATE_MATCH and basis and basis <= _WEAK_IDENTIFIERS:
            raise ValueError("weak_identifiers_only_support_candidate_match")
        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("edge_confidence_out_of_range")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type.value,
            "evidence_ids": list(self.evidence_ids),
            "match_basis": list(self.match_basis),
            "confidence": self.confidence,
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            "time": dict(self.time) if self.time else None,
            "observations": [dict(item) for item in self.observations],
        }


def validate_edges(edges: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    accepted, excluded = [], []
    for raw in edges:
        try:
            accepted.append(TypedEdge.from_dict(raw).to_dict())
        except Exception as exc:
            excluded.append({"candidate": raw, "reason": str(exc)})
    return accepted, excluded


__all__ = ["EdgeType", "TypedEdge", "validate_edges"]
