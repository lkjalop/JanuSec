"""Topology, identity and authorization checks for proposed graph paths."""

from __future__ import annotations

import datetime as dt
from typing import Any, Mapping

from .correlation import EdgeType, validate_edges


def _time(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None


def validate_investigation_paths(
    edges: list[dict[str, Any]], *, records_by_id: Mapping[str, Mapping[str, Any]] | None = None,
    topology_snapshot: Mapping[str, Any] | None = None,
    authorization_snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate paths without treating absent CMDB/IAM data as proof of denial."""

    accepted, structurally_rejected = validate_edges(edges)
    records = records_by_id or {}
    topology = topology_snapshot or {}
    authorization = authorization_snapshot or {}
    from .signed_snapshots import verify_snapshot
    topology_verified, topology_reason = verify_snapshot(topology, expected_kind="topology") if topology else (False, "snapshot_missing")
    authorization_verified, authorization_reason = verify_snapshot(authorization, expected_kind="iam") if authorization else (False, "snapshot_missing")
    # Unsigned or stale snapshots remain visible as context but cannot validate
    # or deny a path. This prevents old IAM/topology state becoming false truth.
    trusted_topology = topology if topology_verified else {}
    trusted_authorization = authorization if authorization_verified else {}
    denied_routes = {tuple(map(str, item)) for item in trusted_topology.get("denied_routes") or [] if isinstance(item, (list, tuple)) and len(item) == 2}
    allowed_routes = {tuple(map(str, item)) for item in trusted_topology.get("allowed_routes") or [] if isinstance(item, (list, tuple)) and len(item) == 2}
    allowed_authorizations = {tuple(map(str, item)) for item in trusted_authorization.get("allowed_paths") or [] if isinstance(item, (list, tuple)) and len(item) == 2}
    rejected = list(structurally_rejected)
    validated: list[dict[str, Any]] = []
    provisional: list[dict[str, Any]] = []

    for edge in accepted:
        pair = (
            str(edge.get("source_ref") or edge["source"]),
            str(edge.get("target_ref") or edge["target"]),
        )
        if pair in denied_routes:
            rejected.append({"candidate": edge, "reason": "topology_explicitly_denies_route"})
            continue
        evidence = [records[eid] for eid in edge.get("evidence_ids") or [] if eid in records]
        times = [_time(item.get("occurred_at") or item.get("valid_from")) for item in evidence]
        times = [value for value in times if value is not None]
        if edge["edge_type"] == EdgeType.OBSERVED_CAUSAL.value and not evidence:
            rejected.append({"candidate": edge, "reason": "causal_edge_evidence_not_present_in_case"})
            continue
        if edge["edge_type"] == EdgeType.CONFIGURED_EXPOSURE.value:
            if allowed_authorizations and pair not in allowed_authorizations:
                provisional.append({**edge, "validation_status": "authorization_path_unconfirmed"})
                continue
        if allowed_routes and pair not in allowed_routes and any("network" in basis or "flow" in basis for basis in edge.get("match_basis") or []):
            provisional.append({**edge, "validation_status": "topology_path_unconfirmed"})
            continue
        validated.append({
            **edge,
            "validation_status": "validated",
            "evidence_time_start": min(times).isoformat() if times else None,
            "evidence_time_end": max(times).isoformat() if times else None,
        })
    gaps: list[str] = []
    if not topology_verified:
        gaps.append(f"Topology snapshot is not authoritative ({topology_reason}); network reachability is unverified.")
    if not authorization_verified:
        gaps.append(f"IAM snapshot is not authoritative ({authorization_reason}); configured access paths are unverified.")
    return {
        "schema_version": "janusec.path-validation/v1",
        "validated_edges": validated,
        "provisional_edges": provisional,
        "rejected_edges": rejected,
        "gaps": gaps,
        "topology_receipt": (topology.get("snapshot_receipt") or {}).get("receipt_hash"),
        "authorization_receipt": (authorization.get("snapshot_receipt") or {}).get("receipt_hash"),
        "snapshot_verification": {"topology": topology_reason, "iam": authorization_reason},
    }


__all__ = ["validate_investigation_paths"]
