"""Build the v2 case projection without inventing evidence relationships."""

from __future__ import annotations

import hashlib
import json
import copy
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from src.api.models.case_evidence import CaseEvidenceViewModelV2


def scope_case_view_to_partition(view: dict[str, Any], partition: dict[str, Any]) -> dict[str, Any]:
    """Return one evidentiary partition; never leak sibling-case context."""

    scoped = copy.deepcopy(view)
    allowed = {str(value) for value in partition.get("evidence_ids") or []}
    selected_case_id = str(partition.get("case_id") or "")
    case_projection = (scoped.pop("_graph_projections_by_case", {}) or {}).get(str(partition.get("case_id") or ""))
    if isinstance(case_projection, dict) and isinstance(case_projection.get("receipt"), dict):
        receipt = case_projection["receipt"]
        scoped.setdefault("report_context", {}).update({
            "graph_projection_id": receipt.get("projection_id"),
            "graph_receipt_hash": receipt.get("content_hash"),
            "graph_ledger_head_hash": receipt.get("ledger_head_hash"),
            "graph_clock_calibration_hash": receipt.get("clock_calibration_hash"),
            "graph_projection_status": case_projection.get("status", "current"),
            "graph_staleness_reasons": list(case_projection.get("staleness_reasons") or []),
        })
    receipts_by_case = scoped.pop("_evidence_pack_receipts_by_case", {}) or {}
    # The base view is assessment-scoped. Replace its receipt list at this
    # boundary so a selected case can never display a sibling case's pack.
    scoped.setdefault("report_context", {})["evidence_pack_receipts"] = [
        dict(item)
        for item in receipts_by_case.get(selected_case_id) or []
        if isinstance(item, dict)
    ]

    def intersects(item: dict[str, Any], keys: tuple[str, ...]) -> bool:
        refs = {str(value) for key in keys for value in (item.get(key) or [])}
        return bool(refs) and refs <= allowed

    scoped["claims"] = [
        item for item in scoped.get("claims") or []
        if isinstance(item, dict) and intersects(item, ("supporting_evidence_ids", "contradicting_evidence_ids"))
    ]
    story = dict(scoped.get("attack_story") or {})
    raw_milestones = [
        item for item in story.get("event_drilldown") or []
        if isinstance(item, dict) and intersects(item, ("evidence_ids",))
    ]
    story["event_drilldown"] = raw_milestones
    story["milestones"] = [
        item for item in story.get("milestones") or []
        if isinstance(item, dict) and intersects(item, ("evidence_ids",))
    ]
    for key in ("entry_vector", "blast_radius"):
        item = story.get(key)
        if not isinstance(item, dict) or not intersects(item, ("evidence_ids",)):
            story[key] = None if key == "entry_vector" else {}
    for key in ("propagation_path", "persistence", "impact_mechanism"):
        story[key] = [item for item in story.get(key) or []
                      if isinstance(item, dict) and intersects(item, ("evidence_ids",))]
    scoped["attack_story"] = story
    scoped["authorization_paths"] = [
        item for item in scoped.get("authorization_paths") or []
        if isinstance(item, dict) and intersects(item, ("evidence_ids",))
    ]
    for collection in ("containment", "immediate_decisions", "control_impacts", "grc_assignments", "corrective_actions",
                       "business_impact", "hypotheses", "grc_workflow"):
        scoped[collection] = [
            item for item in scoped.get(collection) or []
            if isinstance(item, dict) and (
                intersects(item, ("evidence_ids", "supporting_evidence_ids", "verification_evidence_ids"))
                or item.get("case_id") == selected_case_id
            )
        ]
    evidence = dict(scoped.get("evidence") or {})
    evidence["rows"] = [item for item in evidence.get("rows") or [] if str(item.get("id")) in allowed]
    evidence["total"] = len(allowed)
    evidence["returned"] = len(evidence["rows"])
    evidence["truncated"] = len(evidence["rows"]) < len(allowed)
    scoped["evidence"] = evidence
    # Rebase completeness to the selected immutable case partition. The base
    # assessment ratio compares a UI preview with every uploaded telemetry row,
    # which makes a complete 163-row case in a 98k-row upload misleadingly show
    # as 1% complete.
    scoped.setdefault("posture", {})["evidence_completeness"] = (
        round(len(evidence["rows"]) / len(allowed), 4) if allowed else 0.0
    )
    missing_case_refs = max(0, len(allowed) - len(evidence["rows"]))
    if missing_case_refs:
        scoped.setdefault("coverage_gaps", []).append(
            f"{missing_case_refs} case evidence reference(s) were unavailable to the case projection."
        )
    scoped["timeline"] = [
        item for item in scoped.get("timeline") or []
        if str(item.get("evidence_id") or item.get("id")) in allowed
    ]
    assessment_id = (scoped.get("case") or {}).get("assessment_id") or (scoped.get("case") or {}).get("id")
    scoped["case"] = {
        **dict(scoped.get("case") or {}),
        "id": partition.get("case_id"),
        "assessment_id": assessment_id,
        "partition_id": partition.get("partition_id"),
        "partition_hash": partition.get("content_hash"),
        "verdict": partition.get("verdict"),
    }
    scoped["breach_summary"] = {
        **dict(scoped.get("breach_summary") or {}),
        "headline": partition.get("title") or partition.get("case_id"),
        "what_happened": (
            f"Case-scoped projection containing {len(allowed)} evidence references across "
            f"{len(partition.get('episodes') or [])} immutable episodes. "
            "Narration and retrieval are restricted to this partition."
        ),
        "supporting_evidence_ids": sorted(allowed)[:100],
    }
    scoped["case_partitions"] = [{
        "case_id": partition.get("case_id"),
        "partition_id": partition.get("partition_id"),
        "content_hash": partition.get("content_hash"),
        "verdict": partition.get("verdict"),
        "episode_count": len(partition.get("episodes") or []),
    }]
    action_plan = dict(scoped.get("action_plan") or {})
    action_plan["case_id"] = selected_case_id
    action_plan["actions"] = [
        item for item in action_plan.get("actions") or []
        if isinstance(item, dict) and (
            intersects(item, ("supporting_evidence_ids",))
        )
    ]
    action_plan["decisions_required"] = [
        item for item in action_plan.get("decisions_required") or []
        if isinstance(item, dict) and intersects(item, ("evidence_ids", "supporting_evidence_ids"))
    ]
    action_plan["content_hash"] = _canonical_hash({
        key: value for key, value in action_plan.items() if key != "content_hash"
    })
    scoped["action_plan"] = action_plan
    if not scoped["business_impact"]:
        scoped["compliance_obligations"] = {"decision_status": "insufficient_information", "obligations": []}
    return scoped


_DOMAIN_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("email", ("email", "exchange", "gmail", "m365", "proofpoint", "mimecast", "dkim")),
    ("cloud_aws", ("aws", "cloudtrail", "guardduty", "securityhub", "vpc_flow", "s3")),
    ("cloud_azure", ("azure", "entra", "defender", "sentinel", "nsg", "sharepoint")),
    ("cloud_gcp", ("gcp", "google_cloud", "gcloud", "workspace")),
    ("cloud_alibaba", ("alibaba", "aliyun", "alicloud")),
    ("virtualization_nutanix", ("nutanix", "prism", "ahv")),
    ("virtualization_vmware", ("vmware", "vsphere", "esxi", "vcenter")),
    ("infrastructure_hpe", ("hpe", "aruba", "oneview", "ilo")),
    ("endpoint_ebpf", ("ebpf", "bpf", "falco", "tetragon")),
    ("endpoint_sysmon", ("sysmon", "eventid", "windows_event", "wef")),
    ("network_suricata", ("suricata", "eve.json", "ids", "ips")),
    ("network_firewall", ("firewall", "pan-os", "fortigate", "opnsense", "pfsense", "nsg")),
    ("network", ("network", "zeek", "dns", "proxy", "flow", "pcap", "netflow", "ipfix")),
    ("endpoint", ("endpoint", "edr", "process", "auditd", "osquery", "kubernetes", "k8s")),
    ("identity", ("identity", "iam", "kerberos", "oauth", "authentication", "signin")),
    ("data", ("data", "database", "storage", "file", "exfil")),
)


def source_domain(row: dict[str, Any]) -> str:
    text = " ".join(
        str(row.get(key) or "").lower()
        for key in ("source", "source_type", "_source", "_source_type", "provider", "log_type", "source_file")
    )
    for domain, markers in _DOMAIN_MARKERS:
        if any(marker in text for marker in markers):
            return domain
    return "other"


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _refs(values: Any, row_map: dict[str, str]) -> list[str]:
    return [row_map.get(str(value), str(value)) for value in (values or [])]


def _status_from_cluster(cluster: dict[str, Any]) -> str:
    verdict = str(cluster.get("final_verdict") or cluster.get("verdict") or "").upper()
    if "VALIDATED" in verdict or "CONFIRMED" in verdict:
        return "observed"
    if "SUSPECTED" in verdict or "LIKELY" in verdict:
        return "suspected"
    if "DENIED" in verdict or "BLOCK" in verdict:
        return "denied"
    return "unknown"


def _milestones(
    clusters: list[dict[str, Any]], row_map: dict[str, str],
    row_by_ref: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    row_by_ref = row_by_ref or {}
    for index, cluster in enumerate(clusters[:100]):
        raw_phases = cluster.get("phases")
        phase_items = raw_phases if isinstance(raw_phases, list) else [raw_phases] if isinstance(raw_phases, dict) else [{}]
        window = cluster.get("time_window") if isinstance(cluster.get("time_window"), dict) else {}
        for phase_index, phase in enumerate(phase_items):
            phase_id = str(phase.get("phase_id") or phase.get("id") or "investigation")
            title = str(phase.get("name") or phase_id.replace("_", " ").title())
            case_role = str(phase.get("case_role") or cluster.get("kill_chain_stage") or "investigation").replace("_", " ")
            phase_row_refs = phase.get("row_refs") or cluster.get("row_refs") or []
            supporting_rows = [row_by_ref[str(ref)] for ref in phase_row_refs if str(ref) in row_by_ref]
            observed_times = sorted(
                str(value) for row in supporting_rows
                if (value := row.get("occurred_at") or row.get("event_time") or row.get("event_ts") or row.get("timestamp") or row.get("time") or row.get("@timestamp"))
            )
            occurred = observed_times[0] if observed_times else window.get("start")
            if isinstance(occurred, (int, float)):
                occurred = datetime.fromtimestamp(occurred, tz=timezone.utc).isoformat()
            refs = _refs(phase_row_refs, row_map)
            result.append({
                "id": str(phase.get("phase_id") or f"{cluster.get('cluster_id') or index}-phase-{phase_index}"),
                "phase_id": phase_id, "phase": case_role, "title": title,
                "occurred_at": occurred,
                "ended_at": observed_times[-1] if observed_times else occurred,
                "time_basis": "supporting_evidence_event_time" if observed_times else "cluster_window_fallback",
                "status": _status_from_cluster(cluster),
                "summary": str(cluster.get("reason_summary") or cluster.get("short_narrative") or f"{phase.get('row_count') or len(refs)} supporting events."),
                "evidence_ids": refs, "event_count": int(phase.get("row_count") or len(refs)),
                "mitre_techniques": list(phase.get("mitre_techniques") or cluster.get("mitre_techniques") or []),
                "source_domains": sorted({source_domain(row) for row in supporting_rows}) or sorted(set(str(v) for v in (cluster.get("source_types") or []) if v)),
            })
    return sorted(result, key=lambda item: str(item.get("occurred_at") or ""))


def _phase_milestones(raw: list[dict[str, Any]], episodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse event-level chronology into honest phase-level presentation.

    Raw milestones remain available as ``event_drilldown``.  Grouping by phase
    is a presentation projection only; it never creates a causal relationship.
    """
    episode_by_phase: dict[str, list[dict[str, Any]]] = {}
    for episode in episodes:
        if not isinstance(episode, dict) or episode.get("resolution") != "hour":
            continue
        for phase in episode.get("phase_ids") or ["unknown"]:
            episode_by_phase.setdefault(str(phase), []).append(episode)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in raw:
        grouped.setdefault(str(item.get("phase_id") or item.get("phase") or "unknown"), []).append(item)
    output: list[dict[str, Any]] = []
    for phase, items in grouped.items():
        ordered = sorted(items, key=lambda value: str(value.get("occurred_at") or ""))
        refs = sorted({str(ref) for item in items for ref in item.get("evidence_ids") or []})
        statuses = {str(item.get("status") or "unknown") for item in items}
        status = "denied" if statuses == {"denied"} else "observed" if "observed" in statuses else "suspected" if "suspected" in statuses else "unknown"
        phase_episodes = episode_by_phase.get(phase, [])
        episode_starts = sorted(str(item.get("interval_start")) for item in phase_episodes if item.get("interval_start"))
        episode_ends = sorted(str(item.get("interval_end")) for item in phase_episodes if item.get("interval_end"))
        occurred_at = episode_starts[0] if episode_starts else ordered[0].get("occurred_at")
        ended_at = episode_ends[-1] if episode_ends else ordered[-1].get("ended_at") or ordered[-1].get("occurred_at")
        output.append({
            "id": f"phase-{_canonical_hash({'phase': phase, 'refs': refs})[:20]}",
            "phase_id": phase,
            "phase": ordered[0].get("phase") or phase.replace("_", " "),
            "title": ordered[0].get("title") or phase.replace("_", " ").title(),
            "occurred_at": occurred_at,
            "ended_at": ended_at,
            "time_basis": "episode_event_time" if episode_starts else ordered[0].get("time_basis") or "unknown",
            "time_uncertainty_seconds": max((float(item.get("time_uncertainty_seconds") or 0) for item in phase_episodes), default=0.0),
            "status": status,
            "summary": f"{len(items)} observed event{'s' if len(items) != 1 else ''} across {len(phase_episodes)} hourly episode{'s' if len(phase_episodes) != 1 else ''}.",
            "evidence_ids": refs,
            "raw_milestone_ids": [str(item.get("id")) for item in ordered],
            "episode_ids": [str(item.get("episode_id")) for item in phase_episodes],
            "event_count": len(items),
            "mitre_techniques": sorted({str(value) for item in items for value in item.get("mitre_techniques") or []}),
            "source_domains": sorted({str(value) for item in items for value in item.get("source_domains") or []}),
        })
    return sorted(output, key=lambda item: str(item.get("occurred_at") or ""))


def _authorization_paths(rows: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for row, evidence_row in zip(rows, evidence):
        principal = row.get("user") or row.get("user_canonical") or row.get("principal") or row.get("actor")
        action = row.get("action") or row.get("event_name") or row.get("operation") or row.get("Operation")
        resource = (
            row.get("resource") or row.get("target") or row.get("object") or row.get("bucket")
            or row.get("host") or row.get("hostname") or row.get("dst_ip")
        )
        roles = row.get("roles") or row.get("role") or row.get("groups") or []
        policies = row.get("policies") or row.get("policy") or row.get("policy_name") or []
        if not principal or not action or (not resource and not roles and not policies):
            continue
        if not isinstance(roles, list):
            roles = [roles]
        if not isinstance(policies, list):
            policies = [policies]
        raw_outcome = str(row.get("action_outcome") or row.get("outcome") or row.get("result") or row.get("status") or "unknown").lower()
        outcome = "denied" if any(token in raw_outcome for token in ("deny", "fail", "block")) else raw_outcome
        paths.append(
            {
                "id": f"auth-{evidence_row['id']}",
                "principal": str(principal),
                "action": str(action),
                "resource": str(resource or "not_supplied"),
                "outcome": outcome,
                "roles": [str(value) for value in roles if value],
                "policies": [str(value) for value in policies if value],
                "conditions": row.get("conditions") if isinstance(row.get("conditions"), dict) else {},
                "status": "observed",
                "evidence_ids": [evidence_row["id"]],
            }
        )
    return paths[:100]


def _control_impacts(clusters: list[dict[str, Any]], row_map: dict[str, str]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for cluster in clusters:
        register = cluster.get("control_failure_register") or {}
        groups = register.get("control_failures_by_framework") if isinstance(register, dict) else {}
        if not isinstance(groups, dict):
            continue
        cluster_refs = _refs(cluster.get("row_refs"), row_map)
        for framework, items in groups.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict) or not item.get("control_id"):
                    continue
                key = f"{framework}:{item['control_id']}"
                direct_refs = _refs(item.get("evidence_refs"), row_map)
                refs = direct_refs or cluster_refs
                # Telemetry can nominate a weakness; formal nonconformity requires review.
                status = "possible_control_weakness" if refs else "insufficient_grc_evidence"
                entry = by_id.setdefault(
                    key,
                    {
                        "id": key,
                        "framework": str(framework),
                        "control_id": str(item["control_id"]),
                        "title": str(item.get("control_name") or ""),
                        "assertion_status": status,
                        "basis": str(item.get("failure_type") or "candidate mapping from incident behavior"),
                        "confidence": None,
                        "supporting_evidence_ids": [],
                        "contradicting_evidence_ids": [],
                        "missing_evidence": ["Control design and operating-effectiveness evidence requires human review."],
                        "reviewer_status": "unreviewed",
                    },
                )
                entry["supporting_evidence_ids"] = sorted(set(entry["supporting_evidence_ids"] + refs))[:100]
    return list(by_id.values())[:100]


def _decisions(clusters: list[dict[str, Any]], row_map: dict[str, str]) -> list[dict[str, Any]]:
    decisions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cluster in clusters:
        prefill = cluster.get("tier1_prefill") if isinstance(cluster.get("tier1_prefill"), dict) else {}
        actions = prefill.get("immediate_actions") or cluster.get("immediate_actions") or []
        phase_meta = cluster.get("phases") if isinstance(cluster.get("phases"), dict) else {}
        cluster_refs = _refs(cluster.get("row_refs") or phase_meta.get("row_refs"), row_map)
        for item in actions:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title") or item.get("action") or "").strip()
            if not title or title.lower() in seen:
                continue
            seen.add(title.lower())
            decisions.append(
                {
                    "id": f"decision-{len(decisions) + 1}",
                    "decision": title,
                    "priority": str(item.get("priority") or "review"),
                    "rationale": str(item.get("rationale") or ""),
                    "owner_role": str(item.get("persona") or "incident_owner"),
                    "approval_status": "pending",
                    "verification": str(((item.get("subtasks") or [{}])[0]).get("expected_finding") or "") if isinstance(item.get("subtasks"), list) else None,
                    "evidence_ids": cluster_refs,
                }
            )
            if len(decisions) == 3:
                return decisions
    return decisions


def _containment_items(values: Any) -> list[dict[str, Any]]:
    if isinstance(values, dict):
        values = values.get("items") or [values]
    if not isinstance(values, list):
        return []
    output: list[dict[str, Any]] = []
    for index, item in enumerate(values):
        if not isinstance(item, dict):
            continue
        verification_ids = list(item.get("verification_evidence_ids") or [])
        output.append({
            **item,
            "id": str(item.get("id") or f"containment-{index + 1}"),
            "action": str(item.get("action") or item.get("title") or "Containment action"),
            "status": str(item.get("status") or "proposed"),
            "owner_role": str(item.get("owner_role") or item.get("owner") or "incident_owner"),
            "verification_status": str(item.get("verification_status") or ("verified" if verification_ids else "unverified")),
            "verification_evidence_ids": verification_ids,
            "evidence_ids": list(item.get("evidence_ids") or []),
        })
    return output


def _grc_assignments(control_impacts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "id": f"assignment-{item['id']}",
        "control_impact_id": item["id"],
        "owner_role": "control_owner",
        "assignee": None,
        "due_at": None,
        "status": "unassigned",
        "required_evidence": ["Control design evidence", "Operating-effectiveness sample", "Remediation verification"],
        "evidence_ids": list(item.get("supporting_evidence_ids") or []),
        "verification_evidence_ids": [],
    } for item in control_impacts]


def _business_services(values: Any) -> list[dict[str, Any]]:
    """Normalize legacy service maps without manufacturing impact assertions."""
    if isinstance(values, dict):
        values = values.get("services") or [values]
    if not isinstance(values, list):
        return []
    services: list[dict[str, Any]] = []
    for index, item in enumerate(values):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("service") or item.get("business_service") or "").strip()
        if not name:
            continue
        services.append(
            {
                **item,
                "id": str(item.get("id") or f"service-{index + 1}"),
                "name": name,
                "status": str(item.get("status") or "not_assessed"),
                "mapping_source": str(item.get("mapping_source") or "assessment_metadata"),
            }
        )
    return services


def build_case_view_v2(base: dict[str, Any], assessment: dict[str, Any], rows: list[dict[str, Any]], clusters: list[dict[str, Any]]) -> dict[str, Any]:
    """Upgrade the compatible v1-shaped projection to the authoritative v2 contract."""
    evidence_rows = list((base.get("evidence") or {}).get("rows") or [])
    from src.core.evidence_contract.projection_builder import evidence_id_for_row
    from src.core.evidence_contract.semantic_adapters import normalize_semantics

    # A selected case has its own display ID, but its source rows retain the
    # assessment namespace used by custody, partitions and evidence packs.
    case_meta = base.get("case") or {}
    assessment_namespace = str(case_meta.get("assessment_id") or case_meta.get("id") or "assessment")
    row_map: dict[str, str] = {}
    row_by_ref: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        try:
            row_index = int(float(row.get("row_index", index)))
        except (TypeError, ValueError):
            row_index = index
        row_map[str(row_index)] = evidence_id_for_row(
            assessment_namespace, row_index, normalize_semantics(dict(row)),
        )
        row_by_ref[str(row_index)] = row
    domain_counts = Counter(source_domain(row) for row in rows)
    raw_milestones = [
        {
            **dict(item),
            "id": str(item.get("id") or item.get("phase_id")),
            "occurred_at": item.get("occurred_at"),
            "status": "denied" if item.get("action_outcome") == "denied" else "observed",
            "summary": str(item.get("action") or item.get("title") or ""),
        }
        for chronology in assessment.get("case_chronologies") or []
        if isinstance(chronology, dict)
        for item in list(chronology.get("milestones") or []) + list(chronology.get("unsequenced") or [])
        if isinstance(item, dict)
    ]
    selected_partition = assessment.get("_selected_case_partition") if isinstance(assessment.get("_selected_case_partition"), dict) else {}
    episodes = [item for item in selected_partition.get("episodes") or [] if isinstance(item, dict)]
    raw_phase_milestones = _milestones(clusters, row_map, row_by_ref)
    milestones = _phase_milestones(raw_phase_milestones, episodes)
    event_times = {
        str(ref): str(item.get("occurred_at")) for item in raw_milestones
        for ref in item.get("evidence_ids") or [] if item.get("occurred_at")
    }
    for milestone in milestones:
        times = sorted(event_times[ref] for ref in milestone.get("evidence_ids") or [] if ref in event_times)
        if times:
            milestone["occurred_at"], milestone["ended_at"] = times[0], times[-1]
    if not milestones:
        milestones = _phase_milestones(raw_milestones, episodes)
    model_meta = assessment.get("model_execution") if isinstance(assessment.get("model_execution"), dict) else {}
    latest_run = assessment.get("selected_model_run") if isinstance(assessment.get("selected_model_run"), dict) else {}
    explicit_services = assessment.get("business_services") or assessment.get("business_impact") or []
    cmdb_receipt = assessment.get("cmdb_mapping_receipt") if isinstance(assessment.get("cmdb_mapping_receipt"), dict) else None
    from src.core.evidence_contract.signed_snapshots import verify_snapshot
    cmdb_receipt_valid, cmdb_receipt_reason = (
        verify_snapshot(cmdb_receipt, expected_kind="cmdb", tenant_id=str(base["case"].get("tenant_id") or ""))
        if cmdb_receipt else (False, "snapshot_missing")
    )
    normalized_services = _business_services(explicit_services)
    if cmdb_receipt_valid and cmdb_receipt.get("mapped_services_hash") != _canonical_hash(normalized_services):
        cmdb_receipt_valid, cmdb_receipt_reason = False, "mapped_services_hash_mismatch"
    business_services = normalized_services if cmdb_receipt_valid else []
    hypotheses = assessment.get("hypotheses") or assessment.get("alternative_explanations") or []
    if not isinstance(hypotheses, list):
        hypotheses = []
    containment = assessment.get("containment") or assessment.get("containment_status") or []
    if isinstance(containment, dict):
        containment = containment.get("items") or [containment]
    corrective = assessment.get("corrective_actions") or assessment.get("recommendations") or []
    if not isinstance(corrective, list):
        corrective = []
    attack_story = assessment.get("attack_story") if isinstance(assessment.get("attack_story"), dict) else {}
    attack_story = {
        "entry_vector": attack_story.get("entry_vector"),
        "propagation_path": list(attack_story.get("propagation_path") or []),
        "persistence": list(attack_story.get("persistence") or []),
        "impact_mechanism": list(attack_story.get("impact_mechanism") or []),
        "blast_radius": dict(attack_story.get("blast_radius") or {}),
        "milestones": milestones,
        "event_drilldown": raw_phase_milestones or raw_milestones,
    }
    if explicit_services and not cmdb_receipt_valid:
        base.setdefault("coverage_gaps", []).append(
            f"Business-service metadata was supplied without a valid CMDB/service-catalog signed receipt ({cmdb_receipt_reason}) and was not promoted to business impact."
        )
    elif not business_services:
        base.setdefault("coverage_gaps", []).append(
            "Business-service mapping was not supplied; affected technical assets are not promoted to business impact."
        )
    if not milestones:
        base.setdefault("coverage_gaps", []).append(
            "No backend-authored attack milestones are available; the browser will not infer a causal story."
        )
    base["schema_version"] = "janusec.case-evidence-view/v2"
    projection = assessment.get("graph_projection") if isinstance(assessment.get("graph_projection"), dict) else {}
    projection_receipt = projection.get("receipt") if isinstance(projection.get("receipt"), dict) else {}
    case_id = str(base["case"].get("id") or "")
    receipts_by_case = assessment.get("evidence_pack_receipts_by_case") if isinstance(assessment.get("evidence_pack_receipts_by_case"), dict) else {}
    case_pack_receipts = [dict(item) for item in receipts_by_case.get(case_id) or [] if isinstance(item, dict)]
    infrastructure_truth: dict[str, dict[str, Any]] = {}
    for name, kind, key in (
        ("iam", "iam", "authorization_snapshot"),
        ("topology", "topology", "topology_snapshot"),
        ("cmdb", "cmdb", "cmdb_mapping_receipt"),
        ("data_classification", "data_classification", "data_classification_snapshot"),
        ("regulatory_applicability", "regulatory_applicability", "regulatory_applicability_snapshot"),
    ):
        snapshot = assessment.get(key) if isinstance(assessment.get(key), dict) else None
        verified, reason = verify_snapshot(
            snapshot, expected_kind=kind, tenant_id=str(base["case"].get("tenant_id") or ""),
        ) if snapshot else (False, "snapshot_missing")
        receipt = snapshot.get("snapshot_receipt") if snapshot and isinstance(snapshot.get("snapshot_receipt"), dict) else {}
        infrastructure_truth[name] = {
            "status": "verified" if verified else reason,
            "receipt_hash": receipt.get("receipt_hash"),
            "valid_to": receipt.get("valid_to"),
            "version": receipt.get("version"),
        }
    base["report_context"] = {
        "report_id": f"report-{base['case']['id']}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "as_known_at": None,
        "source_updated_at": base["case"].get("updated_at"),
        "evidence_pack_hash": assessment.get("evidence_pack_hash") or _canonical_hash({"case": base["case"]["id"], "claims": base.get("claims"), "evidence": [r.get("id") for r in evidence_rows]}),
        "graph_projection_id": projection_receipt.get("projection_id"),
        "graph_receipt_hash": projection_receipt.get("content_hash"),
        "graph_ledger_head_hash": projection_receipt.get("ledger_head_hash"),
        "graph_clock_calibration_hash": projection_receipt.get("clock_calibration_hash"),
        "graph_projection_status": str(projection.get("status") or "unrecorded"),
        "graph_staleness_reasons": list(projection.get("staleness_reasons") or []),
        "review_status": str(assessment.get("review_status") or "unreviewed"),
        "evidence_pack_receipts": case_pack_receipts,
        "infrastructure_truth": infrastructure_truth,
        "quality_metrics": dict(latest_run.get("evaluation") or assessment.get("quality_metrics") or {}),
    }
    base["model_execution"] = {
        "mode": str(latest_run.get("mode") or model_meta.get("mode") or "deterministic_only"),
        "provider": str(latest_run.get("provider") or model_meta.get("provider") or "deterministic"),
        "model": str(latest_run.get("model") or model_meta.get("model") or "janusec"),
        "run_id": latest_run.get("run_id") or model_meta.get("run_id"),
        "external_data_transfer": bool(latest_run.get("external_data_transfer") or model_meta.get("external_data_transfer")),
        "immutable": True,
        "fallback_applied": bool(latest_run.get("fallback_applied") or model_meta.get("fallback_applied")),
    }
    domain_scope = "returned_evidence_preview" if (base.get("evidence") or {}).get("truncated") else "complete_case_evidence"
    base["source_domains"] = [
        {"domain": domain, "row_count": count, "scope": domain_scope}
        for domain, count in sorted(domain_counts.items())
    ]
    base["attack_story"] = attack_story
    base["business_impact"] = business_services
    base["authorization_paths"] = _authorization_paths(rows, evidence_rows)
    base["containment"] = _containment_items(containment)
    base["immediate_decisions"] = _decisions(clusters, row_map)
    base["hypotheses"] = [item for item in hypotheses if isinstance(item, dict)]
    base["control_impacts"] = _control_impacts(clusters, row_map)
    workflow = [
        dict(item) for item in assessment.get("grc_workflow_events") or []
        if isinstance(item, dict) and str(item.get("case_id") or base["case"]["id"]) == str(base["case"]["id"])
    ]
    latest_workflow: dict[str, dict[str, Any]] = {}
    for item in workflow:
        latest_workflow[str(item.get("finding_id") or item.get("event_id"))] = item
    assignments = _grc_assignments(base["control_impacts"])
    for assignment in assignments:
        event = latest_workflow.get(str(assignment.get("control_impact_id") or ""))
        if event:
            assignment.update({
                "assignee": event.get("control_owner"), "due_at": event.get("due_at"),
                "status": event.get("status"),
                "classification": event.get("classification"),
                "root_cause": event.get("root_cause"), "correction": event.get("correction"),
                "corrective_action": event.get("corrective_action"),
                "compensating_control": event.get("compensating_control"),
                "analyst_signoff": event.get("analyst_signoff"),
                "verification_evidence_ids": list(event.get("verification_evidence_ids") or []),
            })
    base["grc_assignments"] = assignments
    workflow_actions = [{
        "id": item.get("finding_id"), "action": item.get("corrective_action"),
        "owner": item.get("control_owner"), "status": item.get("status"),
        "due_at": item.get("due_at"), "root_cause": item.get("root_cause"),
        "correction": item.get("correction"), "compensating_control": item.get("compensating_control"),
        "verification": ", ".join(item.get("verification_evidence_ids") or []),
        "classification": item.get("classification"), "source_receipt_hash": item.get("content_hash"),
    } for item in latest_workflow.values() if item.get("corrective_action") or item.get("correction")]
    base["corrective_actions"] = workflow_actions or [item for item in corrective if isinstance(item, dict)]
    base["grc_workflow"] = workflow
    from src.core.grc.obligation_engine import evaluate_obligations
    affected_assets = sorted({
        str(value) for service in base["business_impact"]
        for value in service.get("affected_assets") or [] if value
    })
    affected_services = [str(service.get("id")) for service in base["business_impact"] if service.get("id")]
    base["compliance_obligations"] = evaluate_obligations(
        tenant_id=str(base["case"].get("tenant_id") or ""),
        affected_asset_ids=affected_assets, affected_service_ids=affected_services,
        data_classification_snapshot=(assessment.get("data_classification_snapshot") if isinstance(assessment.get("data_classification_snapshot"), dict) else None),
        regulatory_applicability_snapshot=(assessment.get("regulatory_applicability_snapshot") if isinstance(assessment.get("regulatory_applicability_snapshot"), dict) else None),
        incident_facts=(assessment.get("obligation_facts") if isinstance(assessment.get("obligation_facts"), dict) else {}),
    )
    from src.core.grc.action_plan import build_case_action_plan
    base["action_plan"] = build_case_action_plan(
        case_id=str(base["case"].get("id") or ""), containment=base["containment"],
        immediate_decisions=base["immediate_decisions"], control_impacts=base["control_impacts"],
        grc_assignments=base["grc_assignments"],
        infrastructure_truth=base["report_context"].get("infrastructure_truth") or {},
        workflow_events=workflow,
        compliance_obligations=base["compliance_obligations"].get("obligations") or [],
    )
    base["breach_summary"]["coverage_gaps"] = base["coverage_gaps"]
    validated = CaseEvidenceViewModelV2.model_validate(base)
    return validated.model_dump(mode="json")


__all__ = ["build_case_view_v2", "source_domain"]
