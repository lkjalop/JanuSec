"""Hybrid retrieval and immutable CorrectiveRAG Evidence Pack compiler.

The router is deterministic around evidence truth.  A dense provider may rank
documents, but it cannot invent records or promote candidate identity matches
into causal evidence.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .correlation import EdgeType, validate_edges
from .records import canonical_hash

DenseRetriever = Callable[[str, list[dict[str, Any]], int], Iterable[str | dict[str, Any]]]
ContextRetriever = Callable[[str, str, str, int], Iterable[dict[str, Any]]]
ContradictionPolicy = Callable[[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]], Iterable[dict[str, Any]]]


def _timestamp(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except Exception:
        return None


def _record_id(record: Mapping[str, Any]) -> str:
    return str(record.get("evidence_id") or record.get("assertion_id") or record.get("record_id") or "")


def _scalar_values(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for nested in value.values():
            yield from _scalar_values(nested)
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            yield from _scalar_values(nested)
    elif value is not None:
        yield str(value).strip().lower()


def _uncertainty(record: Mapping[str, Any]) -> float:
    try:
        return max(0.0, float(record.get("time_uncertainty_seconds") or 0))
    except (TypeError, ValueError):
        return 0.0


def _clock_offset(calibration: Mapping[str, Any], source: str) -> float:
    value = calibration.get(source)
    if isinstance(value, Mapping):
        value = value.get("offset_seconds")
    try:
        return abs(float(value or 0))
    except (TypeError, ValueError):
        return 0.0


@dataclass(frozen=True, slots=True)
class EvidencePack:
    tenant_id: str
    case_id: str
    query: str
    supporting_evidence: tuple[dict[str, Any], ...]
    contradicting_evidence: tuple[dict[str, Any], ...]
    gaps: tuple[str, ...]
    excluded_candidates: tuple[dict[str, Any], ...]
    lineage: tuple[dict[str, Any], ...]
    versions: dict[str, str]
    retrieval_trace: tuple[dict[str, Any], ...]
    verification: dict[str, Any]
    retrieved_context: tuple[dict[str, Any], ...] = ()
    graph_projection_id: str | None = None
    graph_receipt_hash: str | None = None
    ledger_head_hash: str | None = None
    contradiction_policy_results: tuple[dict[str, Any], ...] = ()
    clock_skew_calibration: dict[str, Any] = field(default_factory=dict)
    alternative_hypothesis_trace: tuple[dict[str, Any], ...] = ()
    excluded_ppr_candidates: tuple[dict[str, Any], ...] = ()
    cmdb_mapping_receipt: dict[str, Any] | None = None
    question_id: str | None = None
    case_partition_hash: str | None = None
    episode_ids: tuple[str, ...] = ()
    corrective_evidence: tuple[dict[str, Any], ...] = ()
    path_validation: dict[str, Any] = field(default_factory=dict)
    corrective_acceptance: dict[str, Any] = field(default_factory=dict)
    assessment_id: str | None = None
    pack_id: str = field(init=False)
    content_hash: str = field(init=False)

    record_type = "evidence_pack"
    schema_version = "janusec.evidence-pack/v2.1"

    def __post_init__(self) -> None:
        digest = canonical_hash(self._content())
        object.__setattr__(self, "content_hash", digest)
        object.__setattr__(self, "pack_id", f"ep2_{digest}")

    def _content(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "record_type": self.record_type,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "query": self.query,
            "supporting_evidence": list(self.supporting_evidence),
            "case_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "retrieved_context": list(self.retrieved_context),
            "gaps": list(self.gaps),
            "excluded_candidates": list(self.excluded_candidates),
            "lineage": list(self.lineage),
            "versions": self.versions,
            "retrieval_trace": list(self.retrieval_trace),
            "verification": self.verification,
            "graph_projection_id": self.graph_projection_id,
            "graph_receipt_hash": self.graph_receipt_hash,
            "ledger_head_hash": self.ledger_head_hash,
            "contradiction_policy_results": list(self.contradiction_policy_results),
            "clock_skew_calibration": self.clock_skew_calibration,
            "alternative_hypothesis_trace": list(self.alternative_hypothesis_trace),
            "excluded_ppr_candidates": list(self.excluded_ppr_candidates),
            "cmdb_mapping_receipt": self.cmdb_mapping_receipt,
            "question_id": self.question_id,
            "case_partition_hash": self.case_partition_hash,
            "episode_ids": list(self.episode_ids),
            "corrective_evidence": list(self.corrective_evidence),
            "path_validation": self.path_validation,
            "corrective_acceptance": self.corrective_acceptance,
            "assessment_id": self.assessment_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._content(), "pack_id": self.pack_id, "content_hash": self.content_hash}


def compile_evidence_pack(
    *,
    tenant_id: str,
    case_id: str,
    query: str,
    records: list[dict[str, Any]],
    identifiers: list[str] | None = None,
    edges: list[dict[str, Any]] | None = None,
    as_known_at: str | None = None,
    max_hops: int = 2,
    limit: int = 200,
    dense_retriever: DenseRetriever | None = None,
    dense_document_retriever: ContextRetriever | None = None,
    temporal_prior_retriever: ContextRetriever | None = None,
    contradiction_policies: list[ContradictionPolicy] | None = None,
    clock_skew_calibration: dict[str, Any] | None = None,
    ppr_candidates: list[dict[str, Any]] | None = None,
    projection_receipt: dict[str, Any] | None = None,
    cmdb_mapping_receipt: dict[str, Any] | None = None,
    required_sensors: list[str] | None = None,
    case_partition: dict[str, Any] | None = None,
    episodes: list[dict[str, Any]] | None = None,
    topology_snapshot: dict[str, Any] | None = None,
    authorization_snapshot: dict[str, Any] | None = None,
    assessment_id: str | None = None,
    expected_evidence_ids: list[str] | None = None,
) -> EvidencePack:
    """Compile a content-addressed pack and run corrective verification.

    Order: exact identifiers -> bitemporal eligibility -> typed causal traversal
    -> lexical -> optional dense documents -> contradiction/gap verification.
    """

    identifiers = [value.strip().lower() for value in identifiers or [] if value and value.strip()]
    terms = [term for term in query.lower().split() if len(term) > 2]
    cutoff = _timestamp(as_known_at)
    trace: list[dict[str, Any]] = []
    selected: dict[str, dict[str, Any]] = {}
    contradicted: dict[str, dict[str, Any]] = {}
    excluded: list[dict[str, Any]] = []
    eligible: list[dict[str, Any]] = []
    partition_evidence_ids = {
        str(value) for value in ((case_partition or {}).get("evidence_ids") or []) if value
    }

    for record in records:
        rid = _record_id(record)
        if not rid:
            excluded.append({"id": "", "reason": "record_missing_stable_id"})
            continue
        if record.get("tenant_id") not in {None, "", tenant_id}:
            excluded.append({"id": rid, "reason": "cross_tenant_record"})
            continue
        if record.get("case_id") not in {None, "", case_id}:
            excluded.append({"id": rid, "reason": "different_case"})
            continue
        if partition_evidence_ids and rid not in partition_evidence_ids and record.get("record_type") == "normalized_evidence_projection":
            excluded.append({"id": rid, "reason": "outside_case_partition"})
            continue
        known = _timestamp(record.get("known_at"))
        valid_from = _timestamp(record.get("valid_from") or record.get("occurred_at"))
        valid_to = _timestamp(record.get("valid_to"))
        if cutoff and ((known and known > cutoff) or (valid_from and valid_from > cutoff) or (valid_to and valid_to <= cutoff)):
            excluded.append({"id": rid, "reason": "outside_bitemporal_cutoff"})
            continue
        eligible.append(record)

    index = {_record_id(record): record for record in eligible}
    trace.append({"stage": "bitemporal_sql", "eligible": len(eligible), "as_known_at": as_known_at})

    for rid, record in index.items():
        values = set(_scalar_values(record))
        if identifiers and any(identifier in values for identifier in identifiers):
            selected[rid] = record
    trace.insert(0, {"stage": "exact_identifiers", "matched": len(selected), "match": "canonical_scalar_equality"})

    from .path_validation import validate_investigation_paths

    path_validation = validate_investigation_paths(
        edges or [], records_by_id=index, topology_snapshot=topology_snapshot,
        authorization_snapshot=authorization_snapshot,
    )
    accepted_edges = [
        {key: value for key, value in edge.items() if key not in {"validation_status", "evidence_time_start", "evidence_time_end"}}
        for edge in path_validation["validated_edges"]
    ]
    # Provisional paths remain visible but cannot expand the evidence set.
    accepted_edges.extend(
        {key: value for key, value in edge.items() if key != "validation_status"}
        for edge in path_validation["provisional_edges"]
        if edge.get("edge_type") == EdgeType.CANDIDATE_MATCH.value
    )
    excluded.extend({"id": "", "reason": item["reason"], "candidate": item["candidate"]} for item in path_validation["rejected_edges"])
    allowed = {EdgeType.OBSERVED_CAUSAL.value, EdgeType.CONFIGURED_EXPOSURE.value}
    traversed_evidence = set(selected)
    # Typed graph endpoints are entity-node IDs, not evidence IDs. Enter the
    # graph only through an edge whose immutable lineage references already
    # selected evidence; shared identifier/candidate edges cannot seed it.
    frontier: set[str] = set()
    for edge in accepted_edges:
        if edge["edge_type"] in allowed and set(edge.get("evidence_ids") or []) & traversed_evidence:
            frontier.update((edge["source"], edge["target"]))
            traversed_evidence.update(
                rid for rid in edge.get("evidence_ids") or [] if rid in index
            )
    traversed_nodes = set(frontier)
    hop_count = max(0, min(max_hops, 4))
    for _ in range(hop_count):
        next_nodes: set[str] = set()
        for edge in accepted_edges:
            if edge["edge_type"] not in allowed:
                continue
            source, target = edge["source"], edge["target"]
            if source in frontier:
                next_nodes.add(target)
                traversed_evidence.update(rid for rid in edge.get("evidence_ids") or [] if rid in index)
            if target in frontier:
                next_nodes.add(source)
                traversed_evidence.update(rid for rid in edge.get("evidence_ids") or [] if rid in index)
        next_nodes -= traversed_nodes
        traversed_nodes |= next_nodes
        frontier = next_nodes
    for rid in traversed_evidence:
        if rid in index:
            selected[rid] = index[rid]
    trace.append({
        "stage": "bounded_typed_traversal", "hops": hop_count,
        "promoted_evidence": len(traversed_evidence), "visited_nodes": len(traversed_nodes),
        "edge_types": sorted(allowed), "entry_policy": "selected_evidence_lineage",
    })

    lexical = 0
    for rid, record in index.items():
        text = " ".join(_scalar_values(record))
        if terms and any(term in text for term in terms):
            if rid not in selected:
                lexical += 1
            selected[rid] = record
    trace.append({"stage": "lexical", "matched": lexical})

    dense_count = 0
    dense_status = "provider_not_configured"
    if dense_retriever is not None:
        dense_status = "ok"
        try:
            for candidate in dense_retriever(query, eligible, limit):
                rid = _record_id(candidate) if isinstance(candidate, Mapping) else str(candidate)
                if rid in index:
                    if rid not in selected:
                        dense_count += 1
                    selected[rid] = index[rid]
                else:
                    excluded.append({"id": rid, "reason": "dense_result_not_in_eligible_corpus"})
        except Exception as exc:  # provider failure is a coverage gap, never fabricated evidence
            dense_status = f"provider_error:{type(exc).__name__}"
    trace.append({"stage": "dense_documents", "matched": dense_count, "status": dense_status})

    retrieved_context: list[dict[str, Any]] = []
    for stage, retriever in (("dense_document_context", dense_document_retriever), ("temporal_prior_cases", temporal_prior_retriever)):
        status, count = "provider_not_configured", 0
        if retriever is not None:
            try:
                for item in retriever(query, tenant_id, case_id, limit):
                    if not isinstance(item, Mapping):
                        continue
                    contextual = dict(item)
                    contextual["context_type"] = stage
                    contextual.setdefault("content_hash", canonical_hash(contextual))
                    retrieved_context.append(contextual)
                    count += 1
                status = "ok"
            except Exception as exc:
                status = f"provider_error:{type(exc).__name__}"
        trace.append({"stage": stage, "matched": count, "status": status, "promoted_to_case_evidence": 0})

    temporal_conflicts: list[str] = []
    for edge in accepted_edges:
        edge_type = edge["edge_type"]
        if edge_type in {EdgeType.CONTRADICTS.value, EdgeType.SUPERSEDES.value} and (
            edge["source"] in selected or edge["target"] in selected
        ):
            correction_ids = list(edge.get("evidence_ids") or [])
            if edge_type == EdgeType.SUPERSEDES.value:
                correction_ids.append(edge["source"])
            for rid in correction_ids:
                if rid in index:
                    contradicted[rid] = index[rid]
        if edge_type == EdgeType.OBSERVED_CAUSAL.value and edge["source"] in index and edge["target"] in index:
            source, target = index[edge["source"]], index[edge["target"]]
            source_time = _timestamp(source.get("occurred_at") or source.get("valid_from"))
            target_time = _timestamp(target.get("occurred_at") or target.get("valid_from"))
            calibration = clock_skew_calibration or {}
            source_name = str(source.get("source") or source.get("source_type") or "")
            target_name = str(target.get("source") or target.get("source_type") or "")
            tolerance = _uncertainty(source) + _uncertainty(target)
            tolerance += _clock_offset(calibration, source_name)
            tolerance += _clock_offset(calibration, target_name)
            if source_time and target_time and source_time > target_time + dt.timedelta(seconds=tolerance):
                source_min = source_time - dt.timedelta(seconds=tolerance)
                target_max = target_time + dt.timedelta(seconds=tolerance)
                temporal_conflicts.append(
                    f"Causal order conflicts outside calibrated time ranges: {edge['source']} "
                    f"[{source_min.isoformat()}, {source_time.isoformat()}] -> {edge['target']} "
                    f"[{target_time.isoformat()}, {target_max.isoformat()}]."
                )

    # Corrective retrieval is a real second pass. Search the still-eligible case
    # corpus for opposite outcomes and revocation/failure evidence sharing a
    # high-specificity entity with the initial result. Keep it separate from
    # support so retrieval cannot silently reverse evidentiary meaning.
    corrective: dict[str, dict[str, Any]] = {}
    entity_keys = {
        "principal_id", "user_canonical", "user", "hostname", "host", "process_id",
        "resource_id", "target_resource", "object_key", "file_hash", "sha256",
    }
    entity_values = {
        str(record.get(key)).strip().lower()
        for record in selected.values() for key in entity_keys
        if record.get(key) not in (None, "")
    }
    corrective_tokens = ("deny", "denied", "fail", "failed", "error", "revoke", "revoked", "remove", "removed", "block", "blocked", "quarantine", "restore")
    for rid, record in index.items():
        if rid in selected:
            continue
        values = {
            str(record.get(key)).strip().lower() for key in entity_keys if record.get(key) not in (None, "")
        }
        text = " ".join(_scalar_values(record))
        if entity_values & values and any(token in text for token in corrective_tokens):
            corrective[rid] = record
            if len(corrective) >= limit:
                break
    trace.append({
        "stage": "corrective_retrieval", "strategy": "shared_specific_entity_plus_alternative_outcome",
        "added": len(corrective), "added_evidence_ids": sorted(corrective),
        "changed_evidence_set": bool(corrective),
    })

    expected_ids = {str(value) for value in expected_evidence_ids or [] if value}
    initial_ids = set(selected)
    corrected_ids = initial_ids | set(corrective)
    initial_recall = (len(initial_ids & expected_ids) / len(expected_ids)) if expected_ids else None
    corrected_recall = (len(corrected_ids & expected_ids) / len(expected_ids)) if expected_ids else None
    recall_improved = bool(
        initial_recall is not None and corrected_recall is not None and corrected_recall > initial_recall
    )
    corrective_acceptance = {
        "changed_evidence_set": bool(corrective),
        "initial_evidence_ids": sorted(initial_ids),
        "added_evidence_ids": sorted(set(corrective)),
        "corrected_evidence_ids": sorted(corrected_ids),
        "truth_set_attached": bool(expected_ids),
        "initial_evidence_recall": initial_recall,
        "corrected_evidence_recall": corrected_recall,
        "recall_improved": recall_improved,
        "accepted": bool(corrective) and recall_improved,
        "outcome": (
            "improved" if bool(corrective) and recall_improved
            else "abstain_no_evidence_delta" if not corrective
            else "abstain_no_measured_gain" if expected_ids
            else "requires_labelled_acceptance_run"
        ),
    }

    policy_results: list[dict[str, Any]] = []
    for policy in contradiction_policies or []:
        try:
            results = [dict(item) for item in policy([*selected.values(), *corrective.values()], eligible, accepted_edges) if isinstance(item, Mapping)]
            policy_results.extend(results)
            for result in results:
                rid = str(result.get("evidence_id") or result.get("record_id") or "")
                if rid in index:
                    contradicted[rid] = index[rid]
        except Exception as exc:
            policy_results.append({"status": "policy_error", "error": type(exc).__name__})

    gaps: list[str] = []
    if not selected:
        gaps.append("No eligible evidence matched the requested identifiers or retrieval terms.")
    if dense_retriever is None and dense_document_retriever is None:
        gaps.append("Dense document retrieval was not configured; semantic recall was not evaluated.")
    if not projection_receipt:
        gaps.append("No authoritative graph projection receipt was bound to this Evidence Pack.")
    from .signed_snapshots import verify_snapshot
    cmdb_valid, cmdb_reason = (
        verify_snapshot(cmdb_mapping_receipt, expected_kind="cmdb", tenant_id=tenant_id)
        if cmdb_mapping_receipt else (False, "snapshot_missing")
    )
    if not cmdb_valid:
        gaps.append(f"No authoritative CMDB/service-catalog mapping receipt was bound ({cmdb_reason}); business impact cannot be asserted.")
    gaps.extend(path_validation.get("gaps") or [])
    gaps.extend(temporal_conflicts)
    present_sensors = {
        str(record.get("source") or record.get("source_type") or record.get("evidence_type") or "").lower()
        for record in eligible
    }
    missing_sensors = [sensor for sensor in required_sensors or [] if sensor.lower() not in present_sensors]
    if missing_sensors:
        gaps.append("Missing required sensor coverage: " + ", ".join(sorted(missing_sensors)) + ".")
    candidate_edges = sum(1 for edge in accepted_edges if edge["edge_type"] == EdgeType.CANDIDATE_MATCH.value)
    action = "accept"
    if not selected or missing_sensors:
        action = "insufficient_evidence"
    elif contradicted or temporal_conflicts or candidate_edges or corrective:
        action = "refine"
    verification = {
        "action": action,
        "support_count": len(selected),
        "contradiction_count": len(contradicted),
        "temporal_conflict_count": len(temporal_conflicts),
        "candidate_edges_not_promoted": candidate_edges,
        "missing_sensors": sorted(missing_sensors),
        "retrieved_context_count": len(retrieved_context),
        "contradiction_policy_count": len(policy_results),
        "corrective_evidence_count": len(corrective),
        "path_validated_count": len(path_validation.get("validated_edges") or []),
        "path_provisional_count": len(path_validation.get("provisional_edges") or []),
        "path_rejected_count": len(path_validation.get("rejected_edges") or []),
    }
    trace.append({"stage": "corrective_verification", **verification})

    support = tuple(value for key, value in list(selected.items())[:limit] if key)
    contradictions = tuple(value for key, value in list(contradicted.items())[:limit] if key)
    alternative_trace: list[dict[str, Any]] = []
    if temporal_conflicts:
        alternative_trace.append({"hypothesis": "clock_or_delivery_skew", "basis": list(temporal_conflicts)})
    if candidate_edges:
        alternative_trace.append({"hypothesis": "shared_identifier_without_identity", "candidate_edge_count": candidate_edges})
    if missing_sensors:
        alternative_trace.append({"hypothesis": "activity_unobserved_due_to_sensor_gap", "missing_sensors": sorted(missing_sensors)})
    if retrieved_context:
        alternative_trace.append({"hypothesis": "prior_case_similarity_requires_local_corroboration", "context_count": len(retrieved_context)})
    excluded_ppr = tuple({**dict(item), "reason": "shadow_retrieval_not_promoted"} for item in (ppr_candidates or [])[:limit])
    receipt = projection_receipt or {}
    return EvidencePack(
        tenant_id=tenant_id,
        case_id=case_id,
        query=query,
        supporting_evidence=support,
        contradicting_evidence=contradictions,
        gaps=tuple(gaps),
        excluded_candidates=tuple(excluded[:limit]),
        lineage=tuple({"record_id": _record_id(record), "content_hash": record.get("content_hash")} for record in support + contradictions),
        versions={"router": "2.2.0", "corrective_verifier": "1.2.0", "contract": EvidencePack.schema_version},
        retrieval_trace=tuple(trace),
        verification=verification,
        retrieved_context=tuple(retrieved_context[:limit]),
        graph_projection_id=receipt.get("projection_id"),
        graph_receipt_hash=receipt.get("content_hash"),
        ledger_head_hash=receipt.get("ledger_head_hash"),
        contradiction_policy_results=tuple(policy_results[:limit]),
        clock_skew_calibration=dict(clock_skew_calibration or {}),
        alternative_hypothesis_trace=tuple(alternative_trace),
        excluded_ppr_candidates=excluded_ppr,
        cmdb_mapping_receipt=cmdb_mapping_receipt,
        question_id=f"question_{canonical_hash({'case_id': case_id, 'query': query})}",
        case_partition_hash=(case_partition or {}).get("content_hash"),
        episode_ids=tuple(str(item.get("episode_id")) for item in (episodes or []) if item.get("episode_id")),
        corrective_evidence=tuple(corrective.values()),
        path_validation=path_validation,
        corrective_acceptance=corrective_acceptance,
        assessment_id=assessment_id or case_id,
    )


__all__ = ["ContextRetriever", "ContradictionPolicy", "DenseRetriever", "EvidencePack", "compile_evidence_pack"]
