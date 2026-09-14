"""Shared knowledge-time boundary for operator views and exports."""
from copy import deepcopy
from fastapi import HTTPException
from src.core.event_time import event_epoch


def scope_to_knowledge_time(view: dict, as_known_at: str | None) -> dict:
    if not as_known_at:
        return view
    cutoff = event_epoch(as_known_at)
    if cutoff is None:
        raise HTTPException(400, "invalid_as_known_at")
    scoped = deepcopy(view)
    from src.api.models.case_evidence import CaseEvidenceViewModelV2
    scoped = {key: value for key, value in scoped.items() if key in CaseEvidenceViewModelV2.model_fields}
    evidence = scoped["evidence"]
    rows = [r for r in evidence["rows"]
            if (known := event_epoch(r.get("known_at"))) is not None and known <= cutoff]
    allowed = {r["id"] for r in rows}
    evidence.update(rows=rows, total=len(rows), returned=len(rows), truncated=False)
    scoped["timeline"] = [r for r in scoped.get("timeline", [])
                          if (r.get("evidence_id") or r.get("id")) in allowed]
    # Current derived conclusions are not historical records. Withhold them
    # until a versioned derivation/receipt proves they existed at the cutoff.
    for key in ("claims", "authorization_paths", "containment", "immediate_decisions",
                "control_impacts", "grc_assignments", "corrective_actions", "case_partitions",
                "hypotheses", "business_impact", "grc_workflow", "source_domains", "retrieval_trace"):
        scoped[key] = []
    scoped["graph"].update(nodes=[], edges=[], excluded_edges=[])
    scoped["attack_story"] = {}
    from src.core.grc.action_plan import build_case_action_plan
    scoped["action_plan"] = build_case_action_plan(
        case_id=scoped["case"]["id"], containment=[], immediate_decisions=[],
        control_impacts=[], grc_assignments=[], infrastructure_truth={},
    )
    scoped["compliance_obligations"] = {"decision_status": "insufficient_information", "obligations": []}
    scoped["analyst"] = {}
    scoped["execution"] = {"historical_derivation": "unavailable"}
    scoped["model_execution"] = {"mode": "deterministic_only", "model": "historical-evidence-filter"}
    scoped["case"]["verdict"] = "ANALYSIS_INCOMPLETE"
    scoped["posture"] = {"verdict": "ANALYSIS_INCOMPLETE", "evidence_confidence": None}
    gap = "Historical evidence view: versioned conclusions are unavailable; current verdicts and actions are withheld. Rows without knowledge timestamps are excluded."
    scoped["coverage_gaps"] = [gap]
    scoped["breach_summary"].update(
        headline="Evidence known at the selected time", what_happened=gap,
        status="provisional", supporting_evidence_ids=sorted(allowed), coverage_gaps=[gap],
    )
    scoped["report_context"].update(
        as_known_at=as_known_at, graph_projection_status="unavailable",
        evidence_pack_receipts=[], acceptance_truth={}, quality_metrics={},
        infrastructure_truth={}, graph_receipt_hash=None, graph_projection_id=None,
    )
    return scoped
