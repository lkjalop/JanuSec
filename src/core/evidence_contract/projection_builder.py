"""Build a conservative authoritative typed case graph from normalized rows."""

from __future__ import annotations

import datetime as dt
from typing import Any

from .correlation import EdgeType, TypedEdge
from .semantic_adapters import normalize_semantics
from .graph_projection import (
    GRAPH_PROJECTION_VERSION,
    MAPPING_VERSION,
    NORMALIZER_VERSION,
    GraphProjectionReceipt,
)
from .records import canonical_hash


def _value(row: dict[str, Any], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _time(row: dict[str, Any]) -> str | None:
    return _value(row, "occurred_at", "event_time", "event_ts", "timestamp", "time", "@timestamp") or None


def _utc_time(value: Any, *, correction_seconds: float = 0.0) -> str | None:
    if value in (None, ""):
        return None
    parsed: dt.datetime
    try:
        if isinstance(value, dt.datetime):
            parsed = value
        elif isinstance(value, (int, float)):
            numeric = float(value)
            if abs(numeric) >= 1e11:
                numeric /= 1000.0
            parsed = dt.datetime.fromtimestamp(numeric, tz=dt.timezone.utc)
        else:
            text = str(value).strip()
            if text.replace(".", "", 1).isdigit():
                return _utc_time(float(text), correction_seconds=correction_seconds)
            parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text)
    except (OSError, OverflowError, TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    parsed = parsed.astimezone(dt.timezone.utc) + dt.timedelta(seconds=correction_seconds)
    return parsed.isoformat().replace("+00:00", "Z")


def _clock_metadata(
    row: dict[str, Any], source: str, clock_calibration: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    calibration = clock_calibration.get(source) if isinstance(clock_calibration.get(source), dict) else {}
    correction = float((calibration or {}).get("correction_seconds") or 0.0)
    uncertainty = max(
        float(row.get("clock_uncertainty_seconds") or row.get("time_uncertainty_seconds") or 0.0),
        float((calibration or {}).get("uncertainty_seconds") or 0.0),
    )
    raw_occurred = _time(row)
    return {
        "occurred_at": _utc_time(raw_occurred, correction_seconds=correction),
        "observed_at": _utc_time(_value(row, "observed_at", "collected_at", "sensor_observed_at")),
        "ingested_at": _utc_time(_value(row, "ingested_at", "ingest_time")),
        "known_at": _utc_time(_value(row, "known_at", "system_available_at", "available_at")),
        "valid_from": _utc_time(_value(row, "valid_from")),
        "valid_to": _utc_time(_value(row, "valid_to")),
        "original_timestamp": str(raw_occurred) if raw_occurred not in (None, "") else None,
        "time_precision": str(row.get("time_precision") or "unknown"),
        "clock_offset_seconds": float(row.get("clock_offset_seconds") or 0.0),
        "clock_correction_seconds": correction,
        "clock_uncertainty_seconds": uncertainty,
        "clock_calibration_version": (calibration or {}).get("version"),
    }


def _node_id(tenant_id: str, case_id: str, kind: str, value: str) -> str:
    return f"{kind}:{canonical_hash({'tenant': tenant_id, 'case': case_id, 'value': value.lower()})[:24]}"


def evidence_id_for_row(case_id: str, index: int, row: dict[str, Any]) -> str:
    """Stable evidence reference shared by graph edges and Evidence Packs."""

    explicit = _value(row, "evidence_id", "row_id")
    if explicit:
        return explicit
    return f"row_{canonical_hash({'case': case_id, 'index': row.get('row_index', index), 'row': row})}"


def infrastructure_receipt_hash(snapshot: Any) -> str | None:
    if not isinstance(snapshot, dict):
        return None
    receipt = snapshot.get("snapshot_receipt")
    return str(receipt.get("receipt_hash")) if isinstance(receipt, dict) and receipt.get("receipt_hash") else None


def infrastructure_valid_to(snapshot: Any) -> str | None:
    if not isinstance(snapshot, dict):
        return None
    receipt = snapshot.get("snapshot_receipt")
    return str(receipt.get("valid_to")) if isinstance(receipt, dict) and receipt.get("valid_to") else None


def build_typed_projection(
    *, tenant_id: str, case_id: str, rows: list[dict[str, Any]], ledger_head_hash: str,
    topology_valid_to: str | None = None, row_limit: int | None = None,
    clock_calibration: dict[str, dict[str, Any]] | None = None,
    evidence_namespace: str | None = None,
    iam_receipt_hash: str | None = None,
    topology_receipt_hash: str | None = None,
    cmdb_receipt_hash: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], GraphProjectionReceipt]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    node_refs: dict[str, str] = {}
    watermarks: dict[str, str] = {}

    clock_calibration = clock_calibration or {}
    clock_calibration_hash = canonical_hash(clock_calibration)

    def node(
        kind: str, value: str, *, clock: dict[str, Any] | None = None,
        labels: list[str] | None = None, role: str | None = None,
    ) -> str:
        nid = _node_id(tenant_id, case_id, kind, value)
        node_refs[nid] = value
        clock = clock or {}
        nodes.setdefault(nid, {
            "node_id": nid, "tenant_id": tenant_id, "kind": kind,
            "labels": labels or [value],
            "occurred_at": clock.get("occurred_at"),
            "observed_at": clock.get("observed_at"),
            "ingested_at": clock.get("ingested_at"),
            "known_at": clock.get("known_at"),
            "valid_from": clock.get("valid_from"),
            "valid_to": clock.get("valid_to"),
            "original_timestamp": clock.get("original_timestamp"),
            "time_precision": clock.get("time_precision", "unknown"),
            "clock_offset_seconds": clock.get("clock_offset_seconds", 0.0),
            "clock_correction_seconds": clock.get("clock_correction_seconds", 0.0),
            "time_uncertainty_seconds": clock.get("clock_uncertainty_seconds", 0.0),
            "clock_calibration_version": clock.get("clock_calibration_version"),
            "topology": [],
            "roles": [role] if role else [],
        })
        if role and role not in nodes[nid]["roles"]:
            nodes[nid]["roles"].append(role)
        return nid

    def edge(
        source: str, target: str, edge_type: EdgeType, evidence_id: str, basis: list[str],
        *, clock: dict[str, Any] | None = None,
    ) -> None:
        if not source or not target or source == target:
            return
        candidate = TypedEdge(
            source, target, edge_type, (evidence_id,), tuple(basis), None,
            node_refs.get(source), node_refs.get(target), dict(clock or {}),
            ({"evidence_id": evidence_id, **dict(clock or {})},),
        )
        candidate.validate()
        raw = candidate.to_dict()
        semantic_key = canonical_hash({
            "source": source,
            "target": target,
            "edge_type": edge_type.value,
            "match_basis": sorted(basis),
        })
        existing = edges.get(semantic_key)
        if existing is None:
            edges[semantic_key] = raw
        else:
            existing["evidence_ids"] = sorted({*(existing.get("evidence_ids") or []), evidence_id})
            existing.setdefault("observations", []).append({"evidence_id": evidence_id, **dict(clock or {})})

    projection_rows = rows if row_limit is None else rows[: max(0, row_limit)]
    for index, original in enumerate(projection_rows):
        if not isinstance(original, dict):
            continue
        row = normalize_semantics(dict(original))
        evidence_id = evidence_id_for_row(evidence_namespace or case_id, index, row)
        source = (_value(row, "source_type", "_source_type", "cloud_provider") or "unknown").lower()
        clock = _clock_metadata(row, source, clock_calibration)
        watermark = clock.get("observed_at") or clock.get("occurred_at")
        if watermark and (source not in watermarks or watermark > watermarks[source]):
            watermarks[source] = watermark

        principal = _value(row, "actor_id", "principal_id", "user_canonical", "user", "userName", "actor", "mailbox")
        src_ip = _value(row, "src_ip", "source_ip", "sourceIPAddress", "client_ip")
        dst_ip = _value(row, "dst_ip", "destination_ip", "remote_ip")
        process = _value(row, "process", "process_name", "Image", "image")
        parent = _value(row, "parent_process", "parent_image", "ParentImage")
        process_pid = _value(row, "process_id", "pid", "ProcessId")
        parent_pid = _value(row, "parent_process_id", "ppid", "ParentProcessId")
        host = _value(row, "host", "hostname", "Computer", "device_name")
        resource = _value(row, "target_resource", "resource_id", "resourceName", "object_key", "bucket")
        destination = _value(row, "destination", "forward_to", "ForwardTo", "external_recipient")

        principal_id = node("principal", principal, clock=clock, role="actor") if principal else ""
        host_id = node("asset", host, clock=clock, role="affected_asset") if host else ""
        src_id = node("address", src_ip, clock=clock, role="source") if src_ip else ""
        dst_id = node("address", dst_ip, clock=clock, role="destination") if dst_ip else ""
        process_key = "|".join(value for value in (host, process_pid, process) if value)
        parent_key = "|".join(value for value in (host, parent_pid, parent) if value)
        process_id = node("process", process_key, clock=clock, labels=[process, process_pid, host], role="instrument") if process_key else ""
        parent_id = node("process", parent_key, clock=clock, labels=[parent, parent_pid, host], role="instrument") if parent_key else ""
        if principal_id and src_id:
            edge(src_id, principal_id, EdgeType.CANDIDATE_MATCH, evidence_id, ["source_ip", "same_event"], clock=clock)
        if src_id and dst_id and row.get("action_outcome") != "denied":
            edge(src_id, dst_id, EdgeType.OBSERVED_INTERACTION, evidence_id, ["observed_network_flow"], clock=clock)
        if process_id and parent_id and (parent or parent_pid):
            edge(parent_id, process_id, EdgeType.OBSERVED_CAUSAL, evidence_id, ["process_parentage"], clock=clock)
        if host_id and process_id:
            edge(host_id, process_id, EdgeType.OBSERVED_INTERACTION, evidence_id, ["process_observed_on_asset"], clock=clock)
        if principal_id and process_id:
            edge(principal_id, process_id, EdgeType.OBSERVED_INTERACTION, evidence_id, ["principal_process_same_event"], clock=clock)
        if process_id and dst_id and row.get("action_outcome") != "denied":
            edge(process_id, dst_id, EdgeType.OBSERVED_INTERACTION, evidence_id, ["process_network_connection"], clock=clock)
        action = _value(row, "action_name", "eventName", "operation", "Operation").lower()
        if principal_id and resource:
            resource_id = node("data", resource, clock=clock, role="target")
            if any(token in action for token in ("attach", "assign", "addmember", "addtogroup", "grant")):
                edge(principal_id, resource_id, EdgeType.CONFIGURED_EXPOSURE, evidence_id, ["authorization_change"], clock=clock)
            elif row.get("action_direction") == "resource_to_principal" and row.get("action_outcome") != "denied":
                edge(resource_id, principal_id, EdgeType.OBSERVED_INTERACTION, evidence_id, ["successful_resource_read"], clock=clock)
            elif row.get("action_direction") == "principal_to_resource" and row.get("action_outcome") != "denied":
                edge(principal_id, resource_id, EdgeType.OBSERVED_INTERACTION, evidence_id, ["successful_resource_write"], clock=clock)
        if process_id and resource and row.get("action_direction") == "process_to_resource" and row.get("action_outcome") != "denied":
            edge(process_id, node("data", resource, clock=clock, role="target"), EdgeType.OBSERVED_INTERACTION, evidence_id, ["process_resource_access"], clock=clock)
        if principal_id and destination and row.get("action_direction") == "mailbox_to_forward_destination":
            edge(principal_id, node("address", destination, clock=clock, role="destination"), EdgeType.CONFIGURED_EXPOSURE, evidence_id, ["mail_forwarding_rule"], clock=clock)
        if principal_id and destination and row.get("action_direction") == "mailbox_to_external_recipient" and row.get("action_outcome") != "denied":
            edge(principal_id, node("address", destination, clock=clock, role="destination"), EdgeType.OBSERVED_INTERACTION, evidence_id, ["observed_email_delivery"], clock=clock)
        for delegate in row.get("delegated_by") or []:
            if delegate and principal_id and row.get("action_outcome") != "denied":
                edge(
                    node("principal", str(delegate), clock=clock, role="delegator"),
                    principal_id, EdgeType.CONFIGURED_EXPOSURE, evidence_id,
                    ["observed_service_account_delegation"], clock=clock,
                )

    node_rows = sorted(nodes.values(), key=lambda item: item["node_id"])
    edge_rows = [edges[key] for key in sorted(edges)]
    projection_id = f"gp_{canonical_hash({'version': GRAPH_PROJECTION_VERSION, 'tenant': tenant_id, 'case': case_id, 'ledger': ledger_head_hash, 'clock_calibration': clock_calibration_hash, 'iam_receipt_hash': iam_receipt_hash, 'topology_receipt_hash': topology_receipt_hash, 'cmdb_receipt_hash': cmdb_receipt_hash, 'nodes': [n['node_id'] for n in node_rows], 'edges': edge_rows})}"
    receipt = GraphProjectionReceipt(
        tenant_id=tenant_id, case_id=case_id, projection_id=projection_id,
        ledger_head_hash=ledger_head_hash, node_ids=tuple(n["node_id"] for n in node_rows),
        edge_ids=tuple(canonical_hash(item) for item in edge_rows),
        normalizer_version=NORMALIZER_VERSION, mapping_version=MAPPING_VERSION,
        # A content-addressed projection must produce the same receipt when
        # replayed. Wall-clock build time made identical replays append a new
        # receipt and could conflict after a partial retry.
        built_at=max(watermarks.values(), default="1970-01-01T00:00:00Z"), source_watermarks=watermarks,
        topology_valid_to=topology_valid_to, clock_calibration_hash=clock_calibration_hash,
        iam_receipt_hash=iam_receipt_hash, topology_receipt_hash=topology_receipt_hash,
        cmdb_receipt_hash=cmdb_receipt_hash,
    )
    return node_rows, edge_rows, receipt


async def persist_assessment_projection(
    *, tenant_id: str, case_id: str, rows: list[dict[str, Any]], topology_valid_to: str | None = None,
    clock_calibration: dict[str, dict[str, Any]] | None = None,
    evidence_namespace: str | None = None,
    iam_receipt_hash: str | None = None,
    topology_receipt_hash: str | None = None,
    cmdb_receipt_hash: str | None = None,
) -> dict[str, Any]:
    from src.repositories.evidence_ledger_repo import list_case
    from src.repositories.graph_projection_repo import append_projection
    from .graph_projection import eligible_ledger_head

    ledger_records = await list_case(tenant_id, evidence_namespace or case_id)
    nodes, edges, receipt = build_typed_projection(
        tenant_id=tenant_id, case_id=case_id, rows=rows,
        ledger_head_hash=eligible_ledger_head(ledger_records), topology_valid_to=topology_valid_to,
        clock_calibration=clock_calibration, evidence_namespace=evidence_namespace,
        iam_receipt_hash=iam_receipt_hash, topology_receipt_hash=topology_receipt_hash,
        cmdb_receipt_hash=cmdb_receipt_hash,
    )
    counts = await append_projection(nodes=nodes, edges=edges, receipt=receipt)
    return {
        "status": "current", "receipt": receipt.to_dict(), "write_counts": counts,
        "node_count": len(nodes), "edge_count": len(edges), "source_row_count": len(rows),
    }


__all__ = [
    "build_typed_projection", "evidence_id_for_row", "infrastructure_receipt_hash", "infrastructure_valid_to",
    "persist_assessment_projection",
]
