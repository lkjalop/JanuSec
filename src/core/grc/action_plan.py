"""Evidence-linked operational actions derived from a case view.

The plan is intentionally conservative.  It promotes existing containment and
analyst decisions, but a telemetry-derived control mapping creates a governed
review task rather than an invented technical fix or compliance conclusion.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from src.core.evidence_contract.records import canonical_hash


ACTION_PLAN_SCHEMA_VERSION = "janusec.case-action-plan/v1"

_HORIZON_ORDER = {"now": 0, "24_hours": 1, "7_days": 2, "30_90_days": 3}
_PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "review": 3, "low": 4}


def _strings(values: Any) -> list[str]:
    if values in (None, ""):
        return []
    if isinstance(values, str):
        return [values]
    if not isinstance(values, Iterable) or isinstance(values, Mapping):
        return [str(values)]
    return [str(value) for value in values if value not in (None, "")]


def _evidence(item: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("evidence_ids", "supporting_evidence_ids", "verification_evidence_ids"):
        values.extend(_strings(item.get(key)))
    return sorted(set(values))


def _priority(value: Any, *, default: str = "high") -> str:
    normalized = str(value or default).strip().lower().replace(" ", "_")
    if normalized in {"p0", "urgent", "immediate", "critical"}:
        return "critical"
    if normalized in {"p1", "high"}:
        return "high"
    if normalized in {"p2", "medium", "moderate"}:
        return "medium"
    if normalized in {"p3", "low"}:
        return "low"
    return "review"


def _action_id(case_id: str, item: Mapping[str, Any]) -> str:
    return f"action_{canonical_hash({'case_id': case_id, **dict(item)})[:24]}"


def _base_action(
    *, case_id: str, horizon: str, action_type: str, title: str,
    exact_action: str, why: str, evidence_ids: list[str], priority: str,
    owner_role: str, approver_role: str, recommendation_status: str,
    verification_procedure: str, required_closure_evidence: list[str],
    affected_objects: list[str] | None = None, control_consequence: str = "",
    framework_trace: list[dict[str, Any]] | None = None,
    finding_id: str | None = None, status: str = "proposed",
    residual_risk: str = "Risk remains until the action is independently verified.",
    preconditions: list[str] | None = None, safety_warnings: list[str] | None = None,
    rollback: str = "Record the previous state and maintain an approved recovery path before changing production systems.",
    due_at: str | None = None,
) -> dict[str, Any]:
    content = {
        "horizon": horizon, "action_type": action_type, "title": title,
        "exact_action": exact_action, "why": why,
        "affected_objects": list(affected_objects or []),
        "owner_role": owner_role, "accountable_approver_role": approver_role,
        "priority": priority, "due_within": {
            "now": "4 hours", "24_hours": "24 hours", "7_days": "7 days",
            "30_90_days": "30-90 days",
        }[horizon],
        "due_at": due_at,
        "status": status, "recommendation_status": recommendation_status,
        "preconditions": list(preconditions or ["Confirm the target belongs to this case and preserve current-state evidence."]),
        "safety_warnings": list(safety_warnings or ["Do not delete source telemetry or destroy forensic artefacts."]),
        "supporting_evidence_ids": sorted(set(evidence_ids)),
        "verification_procedure": verification_procedure,
        "required_closure_evidence": list(required_closure_evidence),
        "rollback_or_recovery": rollback, "residual_risk_if_deferred": residual_risk,
        "control_consequence": control_consequence,
        "framework_trace": list(framework_trace or []),
        "mapping_status": "informative_until_grc_review",
        "finding_id": finding_id,
    }
    return {"id": _action_id(case_id, content), **content}


def _framework_trace(control: Mapping[str, Any]) -> list[dict[str, Any]]:
    if not control.get("control_id"):
        return []
    return [{
        "framework": str(control.get("framework") or "unassigned"),
        "control_id": str(control["control_id"]),
        "title": str(control.get("title") or ""),
        "relevance": str(control.get("basis") or "Incident behaviour nominated this control for review."),
        "assertion_status": str(control.get("assertion_status") or "insufficient_grc_evidence"),
    }]


def build_case_action_plan(
    *, case_id: str, containment: list[dict[str, Any]],
    immediate_decisions: list[dict[str, Any]], control_impacts: list[dict[str, Any]],
    grc_assignments: list[dict[str, Any]], infrastructure_truth: Mapping[str, Any],
    workflow_events: list[dict[str, Any]] | None = None,
    compliance_obligations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a deterministic plan whose claims never exceed supplied evidence."""

    actions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(action: dict[str, Any]) -> None:
        key = (action["action_type"], action["exact_action"].strip().lower())
        if key not in seen:
            seen.add(key)
            actions.append(action)

    for item in containment:
        evidence_ids = _evidence(item)
        exact = str(item.get("action") or item.get("title") or "").strip()
        if not exact:
            continue
        verified = str(item.get("verification_status") or "unverified") == "verified"
        add(_base_action(
            case_id=case_id, horizon="now", action_type="containment",
            title=exact, exact_action=exact,
            why=str(item.get("rationale") or item.get("why") or "Reduce the currently suspected attack path while preserving evidence."),
            evidence_ids=evidence_ids, priority=_priority(item.get("priority"), default="critical"),
            owner_role=str(item.get("owner_role") or "incident_owner"),
            approver_role="incident_commander", recommendation_status=(
                "required_response" if evidence_ids else "suggested_investigation"
            ),
            verification_procedure=str(item.get("verification") or "Re-query the authoritative source and confirm the access path or activity is no longer present."),
            required_closure_evidence=_strings(item.get("required_closure_evidence")) or [
                "Before-state receipt", "Provider-native action receipt", "Independent post-action verification receipt",
            ],
            affected_objects=_strings(item.get("object") or item.get("affected_objects")),
            status=str(item.get("status") or ("verified" if verified else "proposed")),
            residual_risk=str(item.get("residual_risk") or "The suspected access path may remain usable until verification succeeds."),
        ))

    for item in immediate_decisions:
        exact = str(item.get("decision") or item.get("action") or "").strip()
        if not exact:
            continue
        evidence_ids = _evidence(item)
        add(_base_action(
            case_id=case_id, horizon="24_hours", action_type="scoping_and_investigation",
            title=exact, exact_action=exact,
            why=str(item.get("rationale") or "Resolve an incident decision that changes containment, scope, recovery, or notification."),
            evidence_ids=evidence_ids, priority=_priority(item.get("priority")),
            owner_role=str(item.get("owner_role") or "incident_owner"),
            approver_role="incident_commander", recommendation_status=(
                "required_decision" if evidence_ids else "suggested_investigation"
            ),
            verification_procedure=str(item.get("verification") or "Record the decision, its evidence basis, approver, and resulting scope change."),
            required_closure_evidence=["Decision record", "Approver identity", "Evidence Pack receipt used for the decision"],
            affected_objects=_strings(item.get("affected_objects")),
            status=str(item.get("approval_status") or "pending"),
        ))

    assignments = {str(item.get("control_impact_id")): item for item in grc_assignments}
    for control in control_impacts:
        finding_id = str(control.get("id") or "")
        evidence_ids = _evidence(control)
        assignment = assignments.get(finding_id, {})
        correction = str(assignment.get("corrective_action") or assignment.get("correction") or "").strip()
        control_label = " ".join(value for value in (
            str(control.get("control_id") or "").strip(), str(control.get("title") or "").strip(),
        ) if value).strip() or "candidate control"
        exact = correction or (
            f"Have the control owner assess {control_label} against the cited incident evidence, "
            "document design and operating effectiveness, and define a tested correction if the weakness is substantiated."
        )
        classification = str(assignment.get("classification") or control.get("assertion_status") or "possible_control_weakness")
        reviewed = classification in {"substantiated_control_failure", "formal_nonconformity", "nonconformity"}
        control_action = _base_action(
            case_id=case_id, horizon="7_days", action_type="control_correction",
            title=f"Review and correct {control_label}", exact_action=exact,
            why=str(control.get("basis") or "Incident telemetry nominated a possible control weakness."),
            evidence_ids=evidence_ids, priority="high",
            owner_role=str(assignment.get("assignee") or assignment.get("owner_role") or "control_owner"),
            approver_role="independent_control_reviewer",
            recommendation_status=("required_correction" if reviewed else "governed_control_review"),
            verification_procedure=(
                "Repeat the approved control test using a representative sample after correction and attach provider-native results."
            ),
            required_closure_evidence=[
                "Control design evidence", "Operating-effectiveness sample",
                "Corrective-action implementation receipt", "Independent retest result",
            ],
            control_consequence=(
                f"{classification}; formal nonconformity requires authorized review."
            ),
            framework_trace=_framework_trace(control), finding_id=finding_id,
            status=str(assignment.get("status") or "unassigned"),
            due_at=str(assignment.get("due_at")) if assignment.get("due_at") else None,
            residual_risk="The control may continue to permit or fail to detect the observed activity until effectiveness is established.",
        )
        if reviewed:
            control_action["mapping_status"] = "human_reviewed_control_conclusion"
        add(control_action)
        add(_base_action(
            case_id=case_id, horizon="30_90_days", action_type="effectiveness_review",
            title=f"Verify sustained effectiveness of {control_label}",
            exact_action=(
                f"Independently retest {control_label} after an operating period and reopen the finding if the weakness recurs."
            ),
            why="Technical correction alone does not demonstrate that a control continues to operate effectively.",
            evidence_ids=evidence_ids, priority="medium", owner_role="control_owner",
            approver_role="auditor_or_independent_reviewer", recommendation_status="verification_required",
            verification_procedure="Sample the control over the approved review period and compare results with the original incident path.",
            required_closure_evidence=["Approved test procedure", "Time-bounded sample", "Independent effectiveness conclusion"],
            control_consequence="Closure remains provisional until sustained operating effectiveness is demonstrated.",
            framework_trace=_framework_trace(control), finding_id=finding_id,
        ))

    for obligation in compliance_obligations or []:
        if not isinstance(obligation, Mapping) or not obligation.get("review_required"):
            continue
        obligation_id = str(obligation.get("obligation_id") or "obligation")
        state = str(obligation.get("decision_status") or "legal_or_privacy_review_required")
        add(_base_action(
            case_id=case_id, horizon="24_hours", action_type="legal_privacy_assessment",
            title=f"Review applicability of {obligation_id}",
            exact_action=(
                f"Have the authorized legal/privacy owner review {obligation_id} using the cited incident facts, "
                "approved applicability profile, and source reference; record the notification decision and rationale."
            ),
            why=f"Obligation engine status: {state}. JanusSec does not make the legal conclusion.",
            evidence_ids=[str(value) for value in obligation.get("supporting_evidence_ids") or []],
            priority="critical" if state == "obligation_likely_triggered" else "high",
            owner_role=str(obligation.get("owner_role") or "legal_privacy_and_grc"),
            approver_role="authorized_legal_or_privacy_reviewer",
            recommendation_status="required_legal_privacy_decision",
            verification_procedure="Attach the signed decision, cited source version, applicable legal entity, and any completed notification receipt.",
            required_closure_evidence=["Authorized legal/privacy decision", "Applicability rationale", "Notification receipt or documented no-notify decision"],
            control_consequence="Compliance status cannot be closed until the authorized obligation decision is recorded.",
            finding_id=f"obligation:{obligation_id}",
        ))

    decisions: list[dict[str, Any]] = []
    truth = {key: value if isinstance(value, Mapping) else {} for key, value in infrastructure_truth.items()}
    if truth.get("iam", {}).get("status") != "verified":
        decisions.append({
            "id": "decision-authorization-scope", "priority": "high",
            "question": "Which identities and authorization paths remain usable?",
            "owner_role": "identity_owner", "due_within": "24 hours",
            "status": "blocked_missing_signed_iam_truth",
            "required_information": ["Fresh signed IAM snapshot", "Session and token state", "Privileged-role assignments"],
        })
    if truth.get("topology", {}).get("status") != "verified":
        decisions.append({
            "id": "decision-reachability-scope", "priority": "high",
            "question": "Which assets and network paths are still reachable from the affected scope?",
            "owner_role": "network_owner", "due_within": "24 hours",
            "status": "blocked_missing_signed_topology_truth",
            "required_information": ["Fresh signed topology snapshot", "Segmentation policy", "Observed flow disposition"],
        })
    if truth.get("cmdb", {}).get("status") != "verified":
        decisions.append({
            "id": "decision-business-impact", "priority": "high",
            "question": "Which business services and obligations are affected?",
            "owner_role": "service_owner_and_grc", "due_within": "24 hours",
            "status": "blocked_missing_signed_asset_service_mapping",
            "required_information": ["Fresh signed asset-to-service mapping", "Data classification", "Applicable legal and contractual obligations"],
        })
    if truth.get("data_classification", {}).get("status") != "verified":
        decisions.append({
            "id": "decision-data-classification", "priority": "high",
            "question": "Was regulated, contractual, or otherwise sensitive data affected?",
            "owner_role": "data_owner_and_privacy", "due_within": "24 hours",
            "status": "blocked_missing_signed_data_classification",
            "required_information": ["Fresh signed asset-to-data-classification mapping", "Affected object identifiers", "Observed access mode"],
        })
    if truth.get("regulatory_applicability", {}).get("status") != "verified":
        decisions.append({
            "id": "decision-regulatory-applicability", "priority": "high",
            "question": "Which legal, regulatory, contractual, or insurance obligations require review?",
            "owner_role": "legal_privacy_and_grc", "due_within": "24 hours",
            "status": "blocked_missing_signed_regulatory_applicability",
            "required_information": ["Versioned obligation profile", "Jurisdiction and legal entity", "Contract and insurance notification clauses"],
        })

    # Missing infrastructure truth is not merely a warning.  Turn each blocked
    # decision into an assignable, approval-gated, read-only collection task so
    # the case has a concrete next step without pretending the missing answer is
    # already known.
    collection_instructions = {
        "decision-authorization-scope": (
            "Collect a fresh, signed, read-only IAM snapshot for the affected identity providers and cloud accounts; include active sessions, privileged assignments, and policy attachments.",
            "Signed IAM receipt and collector execution receipt",
        ),
        "decision-reachability-scope": (
            "Collect a fresh, signed, read-only topology snapshot for affected networks and management planes; include routes, segmentation policy, security rules, and observed flow disposition.",
            "Signed topology receipt and collector execution receipt",
        ),
        "decision-business-impact": (
            "Collect a fresh, signed asset-to-business-service mapping from the authoritative CMDB or service catalogue for the affected asset identifiers.",
            "Signed CMDB mapping receipt with source version",
        ),
        "decision-data-classification": (
            "Collect a fresh, signed data-classification snapshot for the affected assets and objects from the authoritative data catalogue or approved owner record.",
            "Signed data-classification receipt with owner and source version",
        ),
        "decision-regulatory-applicability": (
            "Have the authorized legal/privacy owner attach a signed, versioned applicability profile covering legal entity, jurisdiction, contracts, insurance clauses, and approved source references.",
            "Signed applicability receipt and authorized reviewer identity",
        ),
    }
    for decision in decisions:
        instruction, proof = collection_instructions[decision["id"]]
        add(_base_action(
            case_id=case_id, horizon="24_hours", action_type="evidence_collection",
            title=decision["question"], exact_action=instruction,
            why=f"The case is blocked by {decision['status']}; JanusSec must abstain until authoritative truth is attached.",
            evidence_ids=[], priority=_priority(decision.get("priority")),
            owner_role=str(decision["owner_role"]), approver_role="incident_commander",
            recommendation_status="required_information_collection",
            verification_procedure="Verify the signature, tenant and scope binding, source version, valid time, collector authorization, and freshness policy before rebuilding the case projection.",
            required_closure_evidence=[proof, "Projection rebuild receipt bound to the new snapshot hash"],
            finding_id=str(decision["id"]),
            preconditions=["Collector access is explicitly authorized and read-only.", "Affected tenant, account, subscription, project, or service scope is recorded."],
            safety_warnings=["Do not grant remediation permissions to the collector.", "Do not use the collected metadata to claim impact or compliance until verification succeeds."],
        ))

    latest_workflow: dict[str, dict[str, Any]] = {}
    for event in workflow_events or []:
        if isinstance(event, Mapping):
            latest_workflow[str(event.get("finding_id") or "")] = dict(event)
    for action in actions:
        event = latest_workflow.get(str(action.get("finding_id") or action.get("id") or ""))
        if not event:
            continue
        action.update({
            "status": event.get("status") or action.get("status"),
            "owner_role": event.get("control_owner") or action.get("owner_role"),
            "due_at": event.get("due_at") or action.get("due_at"),
            "last_actor": event.get("actor"), "last_actor_role": event.get("actor_role"),
            "before_evidence_ids": list(event.get("before_evidence_ids") or []),
            "after_evidence_ids": list(event.get("after_evidence_ids") or []),
            "verification_evidence_ids": list(event.get("verification_evidence_ids") or []),
            "workflow_receipt_hash": event.get("content_hash"),
        })

    actions.sort(key=lambda item: (
        _HORIZON_ORDER.get(item["horizon"], 99),
        _PRIORITY_ORDER.get(item["priority"], 99), item["title"].lower(),
    ))
    content = {
        "schema_version": ACTION_PLAN_SCHEMA_VERSION, "case_id": case_id,
        "actions": actions, "decisions_required": decisions,
        "governance_boundary": (
            "Models may propose actions. Authenticated humans approve execution, control conclusions, and closure."
        ),
    }
    return {**content, "content_hash": canonical_hash(content)}


__all__ = ["ACTION_PLAN_SCHEMA_VERSION", "build_case_action_plan"]
