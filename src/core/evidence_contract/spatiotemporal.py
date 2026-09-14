"""Typed spatiotemporal graph contracts for evidence-safe investigation.

This is deliberately a contract, not another graph engine.  HopGraph, a SQL
recursive query, or a research projection may implement it, but none may erase
the epistemic type, role, tenant, or time uncertainty carried here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .correlation import EdgeType, TypedEdge


class NodeKind(str, Enum):
    EVIDENCE = "evidence"
    PRINCIPAL = "principal"
    ASSET = "asset"
    ADDRESS = "address"
    SUBNET = "subnet"
    PROCESS = "process"
    DATA = "data"
    SERVICE = "service"
    AUTHORIZATION = "authorization"
    CTI = "cti"
    CLAIM = "claim"


class CaseRole(str, Enum):
    ACTOR = "actor"
    VICTIM = "victim"
    TARGET = "target"
    INSTRUMENT = "instrument"
    DESTINATION = "destination"
    SERVICE = "service"


class RoleStatus(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    SUSPECTED = "suspected"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class SpatiotemporalNode:
    node_id: str
    tenant_id: str
    kind: NodeKind
    labels: tuple[str, ...] = ()
    occurred_at: str | None = None
    observed_at: str | None = None
    known_at: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None
    time_uncertainty_seconds: float = 0.0
    topology: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SpatiotemporalNode":
        node = cls(
            node_id=str(raw.get("node_id") or "").strip(),
            tenant_id=str(raw.get("tenant_id") or "").strip(),
            kind=NodeKind(raw.get("kind")),
            labels=tuple(str(v) for v in raw.get("labels") or ()),
            occurred_at=raw.get("occurred_at"),
            observed_at=raw.get("observed_at"),
            known_at=raw.get("known_at"),
            valid_from=raw.get("valid_from"),
            valid_to=raw.get("valid_to"),
            time_uncertainty_seconds=float(raw.get("time_uncertainty_seconds") or 0),
            topology=tuple(str(v) for v in raw.get("topology") or ()),
        )
        if not node.node_id or not node.tenant_id:
            raise ValueError("node_requires_id_and_tenant")
        if node.time_uncertainty_seconds < 0:
            raise ValueError("time_uncertainty_must_be_non_negative")
        return node


@dataclass(frozen=True, slots=True)
class RoleAssertion:
    entity_id: str
    role: CaseRole
    status: RoleStatus
    evidence_ids: tuple[str, ...]
    case_id: str
    tenant_id: str
    valid_from: str | None = None
    valid_to: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RoleAssertion":
        assertion = cls(
            entity_id=str(raw.get("entity_id") or "").strip(),
            role=CaseRole(raw.get("role")),
            status=RoleStatus(raw.get("status")),
            evidence_ids=tuple(str(v) for v in raw.get("evidence_ids") or ()),
            case_id=str(raw.get("case_id") or "").strip(),
            tenant_id=str(raw.get("tenant_id") or "").strip(),
            valid_from=raw.get("valid_from"),
            valid_to=raw.get("valid_to"),
        )
        if not assertion.entity_id or not assertion.case_id or not assertion.tenant_id:
            raise ValueError("role_assertion_requires_entity_case_and_tenant")
        if assertion.status is RoleStatus.OBSERVED and not assertion.evidence_ids:
            raise ValueError("observed_role_requires_evidence")
        return assertion


_PURPOSE_EDGE_TYPES: dict[str, frozenset[EdgeType]] = {
    "causal_reconstruction": frozenset({EdgeType.OBSERVED_CAUSAL}),
    "chronology": frozenset({
        EdgeType.OBSERVED_CAUSAL,
        EdgeType.OBSERVED_INTERACTION,
        EdgeType.TEMPORAL_PRECEDES,
    }),
    "exposure_review": frozenset({EdgeType.OBSERVED_CAUSAL, EdgeType.CONFIGURED_EXPOSURE}),
    "candidate_resolution": frozenset({EdgeType.CANDIDATE_MATCH}),
    "claim_verification": frozenset(
        {EdgeType.CLAIM_SUPPORT, EdgeType.CONTRADICTS, EdgeType.SUPERSEDES}
    ),
    "threat_context": frozenset({EdgeType.CTI_RELATION}),
}


def allowed_edge_types(purpose: str) -> frozenset[EdgeType]:
    """Return the smallest edge view allowed for a declared query purpose."""

    try:
        return _PURPOSE_EDGE_TYPES[purpose]
    except KeyError as exc:
        raise ValueError("unknown_graph_query_purpose") from exc


def validate_tenant_graph(
    nodes: list[dict[str, Any]], edges: list[dict[str, Any]], *, tenant_id: str
) -> tuple[list[SpatiotemporalNode], list[TypedEdge]]:
    typed_nodes = [SpatiotemporalNode.from_dict(node) for node in nodes]
    if any(node.tenant_id != tenant_id for node in typed_nodes):
        raise ValueError("cross_tenant_node_rejected")
    node_ids = {node.node_id for node in typed_nodes}
    typed_edges = [TypedEdge.from_dict(edge) for edge in edges]
    if any(edge.source not in node_ids or edge.target not in node_ids for edge in typed_edges):
        raise ValueError("edge_endpoint_missing_or_cross_tenant")
    return typed_nodes, typed_edges


__all__ = [
    "CaseRole",
    "NodeKind",
    "RoleAssertion",
    "RoleStatus",
    "SpatiotemporalNode",
    "allowed_edge_types",
    "validate_tenant_graph",
]
