"""Provider discovery, immutable model runs, comparison, and GRC pack export."""

from __future__ import annotations
from src.security.storage_paths import storage_path, confined_path

import asyncio
import json
import os
import time
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from src.security.auth import require_api_key


router = APIRouter(tags=["case-intelligence"])
_MODEL_JOB_TASKS: dict[str, asyncio.Task] = {}
_GENERATION_CONCURRENCY = max(1, int(os.getenv("MODEL_GENERATION_CONCURRENCY", "1") or 1))
_GENERATION_SEMAPHORE = asyncio.Semaphore(_GENERATION_CONCURRENCY)


def _tenant(request: Request, auth: object) -> str:
    from src.api.ingest_endpoints import _assessment_tenant

    return _assessment_tenant(request, auth)


async def _load_case(assessment_id: str, tenant_id: str) -> dict[str, Any]:
    from src.api.deep_analyze.persistence import _get_assessment_cached
    from src.api.ingest_endpoints import _case_view_model, _owned_job
    from src.core.ingest import store as assessment_store

    job = await asyncio.to_thread(_owned_job, assessment_store, assessment_id, tenant_id)
    assessment = await asyncio.to_thread(_get_assessment_cached, assessment_id)
    if not isinstance(assessment, dict):
        assessment = {}
    if str(assessment.get("org") or tenant_id) != tenant_id:
        raise HTTPException(status_code=404, detail="Assessment not found")
    view = _case_view_model(assessment_id, tenant_id, job, assessment)
    view["case_partitions"] = [dict(item) for item in assessment.get("case_partitions") or [] if isinstance(item, dict)]
    view["_graph_projections_by_case"] = dict(assessment.get("graph_projections_by_case") or {})
    from src.core.acceptance_truth import infer_truth_scenario

    view["_acceptance_truth_scenario"] = infer_truth_scenario(assessment)
    try:
        from src.core.evidence_contract.graph_projection import (
            MAPPING_VERSION,
            NORMALIZER_VERSION,
            GraphProjectionReceipt,
            configured_sensor_slas,
            eligible_ledger_head,
            projection_staleness,
        )
        from src.repositories.evidence_ledger_repo import list_case
        from src.core.evidence_contract.records import canonical_hash
        from src.core.evidence_contract.projection_builder import infrastructure_receipt_hash

        projection = assessment.get("graph_projection") if isinstance(assessment.get("graph_projection"), dict) else {}
        receipt_raw = projection.get("receipt") if isinstance(projection.get("receipt"), dict) else None
        if receipt_raw:
            receipt = GraphProjectionReceipt.from_dict(receipt_raw)
            ledger = await list_case(tenant_id, assessment_id)
            reasons = projection_staleness(
                receipt,
                current_ledger_head_hash=eligible_ledger_head(ledger),
                normalizer_version=NORMALIZER_VERSION,
                mapping_version=MAPPING_VERSION,
                sensor_max_age_seconds=configured_sensor_slas(),
                clock_calibration_hash=canonical_hash(assessment.get("clock_calibration") or {}),
                iam_receipt_hash=infrastructure_receipt_hash(assessment.get("authorization_snapshot")),
                topology_receipt_hash=infrastructure_receipt_hash(assessment.get("topology_snapshot")),
                cmdb_receipt_hash=infrastructure_receipt_hash(assessment.get("cmdb_mapping_receipt")),
            )
            view["report_context"]["graph_projection_status"] = "stale" if reasons else "current"
            view["report_context"]["graph_staleness_reasons"] = [reason.value for reason in reasons]
            if reasons:
                view["coverage_gaps"].append(
                    "Report generated from a stale graph projection; causal conclusions are provisional."
                )
        else:
            view["report_context"]["graph_projection_status"] = "unrecorded"
    except Exception:
        view["report_context"]["graph_projection_status"] = "unavailable"
        view["coverage_gaps"].append("Graph freshness could not be verified for this report.")
    view["breach_summary"]["coverage_gaps"] = list(view["coverage_gaps"])
    return view


@router.get("/api/v1/model-providers")
async def model_providers(
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
    probe_external: bool = False,
) -> dict[str, Any]:
    _tenant(request, auth)
    from src.core.model_provider_registry import discover_providers

    providers = await asyncio.to_thread(discover_providers, probe_external=probe_external)
    return {
        "providers": providers,
        "routing_modes": ["deterministic_only", "local_only", "local_preferred", "paid_allowed", "manual", "compare"],
        "external_fallback_requires_approval": True,
    }


@router.post("/api/v1/model-providers/ollama/probe")
async def ollama_inference_probe(
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> JSONResponse:
    """Run an explicit no-evidence structured-output/context launch probe."""

    _tenant(request, auth)
    body = await request.json()
    model = str(body.get("model") or "").strip()
    if not model:
        raise HTTPException(status_code=422, detail="model_required")
    context_tokens = int(body.get("context_tokens") or 8192)
    timeout = min(600.0, max(5.0, float(body.get("timeout_seconds") or 120.0)))
    from src.core.model_provider_registry import probe_ollama_inference, runtime_provider_config

    result = await asyncio.to_thread(
        probe_ollama_inference,
        model,
        endpoint=runtime_provider_config("ollama").get("url"),
        context_tokens=context_tokens,
        timeout=timeout,
    )
    return JSONResponse(content=result, status_code=200 if result.get("status") == "ok" else 503)


def _prompt(view: dict[str, Any]) -> str:
    def clipped(value: Any, limit: int = 500) -> Any:
        if not isinstance(value, str):
            return value
        return value if len(value) <= limit else value[: limit - 1] + "…"

    def compact_claim(item: dict[str, Any]) -> dict[str, Any]:
        refs = list(item.get("supporting_evidence_ids") or [])
        return {
            key: clipped(item.get(key))
            for key in ("id", "type", "title", "status", "confidence")
        } | {
            "supporting_evidence_ids": refs[:5],
            "supporting_evidence_count": len(refs),
            "contradicting_evidence_ids": list(item.get("contradicting_evidence_ids") or [])[:5],
        }

    def compact_auth(item: dict[str, Any]) -> dict[str, Any]:
        return {key: clipped(item.get(key), 250) for key in (
            "id", "principal", "action", "resource", "outcome", "roles", "policies", "status", "evidence_ids"
        )}

    source_summary = dict(view.get("breach_summary") or {})
    summary = {key: clipped(source_summary.get(key), 1000) for key in (
        "headline", "what_happened", "status", "generated_by", "coverage_gaps"
    )}
    summary_refs = list(source_summary.get("supporting_evidence_ids") or [])
    summary["supporting_evidence_ids"] = summary_refs[:5]
    summary["supporting_evidence_count"] = len(summary_refs)
    story = dict(view.get("attack_story") or {})
    story["milestones"] = [
        {
            **{key: clipped(item.get(key), 400) for key in ("id", "phase", "title", "occurred_at", "status", "summary", "mitre_techniques", "source_domains")},
            "evidence_ids": list(item.get("evidence_ids") or [])[:5],
            "evidence_count": len(item.get("evidence_ids") or []),
        }
        for item in (story.get("milestones") or [])[:6]
        if isinstance(item, dict)
    ]
    controls = [
        {
            **{key: clipped(item.get(key), 300) for key in ("id", "framework", "control_id", "title", "assertion_status", "basis", "confidence", "reviewer_status")},
            "missing_evidence": list(item.get("missing_evidence") or [])[:2],
            "supporting_evidence_ids": list(item.get("supporting_evidence_ids") or [])[:3],
            "supporting_evidence_count": len(item.get("supporting_evidence_ids") or []),
        }
        for item in (view.get("control_impacts") or [])[:3]
        if isinstance(item, dict)
    ]

    compact = {
        "case": view.get("case"),
        "posture": view.get("posture"),
        "breach_summary": summary,
        "claims": [compact_claim(item) for item in (view.get("claims") or [])[:8] if isinstance(item, dict)],
        "attack_story": story,
        "business_impact": view.get("business_impact"),
        "authorization_paths": [compact_auth(item) for item in (view.get("authorization_paths") or [])[:3] if isinstance(item, dict)],
        "coverage_gaps": view.get("coverage_gaps"),
        "control_impacts": controls,
        "source_domains": view.get("source_domains"),
        "evidence_pack_hash": (view.get("report_context") or {}).get("evidence_pack_hash"),
    }
    return (
        "Review this security case projection. Facts must cite existing evidence IDs; do not turn a candidate match into causality. "
        "Return JSON with headline, what_happened, confirmed_impact, suspected_impact, entry_point, persistence, lateral_movement, "
        "data_access_or_exfiltration, alternative_hypotheses, three_immediate_decisions, and coverage_gaps. "
        "Distinguish actors from targets and successful from denied actions. Include overall_confidence from 0 to 1 and "
        "evidence_ids_by_field mapping every factual output field to existing evidence IDs; an uncited field must be marked provisional.\nCASE:\n"
        + json.dumps(compact, ensure_ascii=False, default=str)
    )


def _scope_view_to_partition(view: dict[str, Any], partition: dict[str, Any]) -> dict[str, Any]:
    from src.api.case_view_v2 import scope_case_view_to_partition

    return scope_case_view_to_partition(view, partition)


def _corrective_query(output: Any, evaluation: dict[str, Any], view: dict[str, Any]) -> str:
    """Build a deliberately different query for weak first-pass attribution."""

    citations = output.get("evidence_ids_by_field") if isinstance(output, dict) and isinstance(output.get("evidence_ids_by_field"), dict) else {}
    factual_fields = (
        "what_happened", "confirmed_impact", "suspected_impact", "entry_point", "persistence",
        "lateral_movement", "data_access_or_exfiltration", "alternative_hypotheses",
    )
    weak_fields = [field.replace("_", " ") for field in factual_fields if output and output.get(field) and not citations.get(field)]
    entities: list[str] = []
    for role in view.get("entity_roles") or view.get("roles") or []:
        if isinstance(role, dict):
            value = role.get("entity") or role.get("entity_id")
            if value and str(value) not in entities:
                entities.append(str(value))
    focus = ", ".join(weak_fields[:6]) or "attribution, chronology, impact, and alternatives"
    return (
        f"Corrective verification for {focus}. Search for denied, failed, blocked, revoked, removed, "
        "superseding, baseline, benign, target-role, clock-skew, and alternative-identity evidence. "
        f"Resolve success versus attempt and actor versus victim/target. Entities: {', '.join(entities[:12]) or 'case entities'}. "
        f"Initial attribution={evaluation.get('attribution_quality')}; evidence_recall={evaluation.get('evidence_recall')}."
    )


def _correction_improves(initial: dict[str, Any], candidate: dict[str, Any]) -> bool:
    """Accept a correction only when grounding improves; never prefer fluent prose."""

    initial_score = (
        -float(initial.get("unsupported_claim_rate") or 0),
        float(initial.get("attribution_quality") or 0),
        float(initial.get("evidence_recall") or 0),
        int(initial.get("contradictions_discovered") or 0),
    )
    candidate_score = (
        -float(candidate.get("unsupported_claim_rate") or 0),
        float(candidate.get("attribution_quality") or 0),
        float(candidate.get("evidence_recall") or 0),
        int(candidate.get("contradictions_discovered") or 0),
    )
    return candidate_score > initial_score


def _deterministic_narration(view: dict[str, Any]) -> dict[str, Any]:
    """Render the server-owned evidence projection without invoking an LLM."""

    summary = view.get("breach_summary") if isinstance(view.get("breach_summary"), dict) else {}
    milestones = [item for item in (view.get("attack_story") or {}).get("milestones") or [] if isinstance(item, dict)]
    summary_ids = [str(value) for value in summary.get("supporting_evidence_ids") or []]
    by_phase: dict[str, list[dict[str, Any]]] = {}
    for item in milestones:
        by_phase.setdefault(str(item.get("phase") or ""), []).append(item)

    def phase_text(phases: tuple[str, ...], fallback: str) -> tuple[str, list[str]]:
        selected = [item for phase in phases for item in by_phase.get(phase, [])]
        if not selected:
            return fallback, []
        text = " ".join(str(item.get("summary") or item.get("title") or "") for item in selected).strip()
        ids = [str(value) for item in selected for value in item.get("evidence_ids") or []]
        return text or fallback, list(dict.fromkeys(ids))

    entry, entry_ids = phase_text(("initial_access",), "provisional: entry point not established")
    persistence, persistence_ids = phase_text(("persistence",), "provisional: persistence not established")
    lateral, lateral_ids = phase_text(("lateral_movement",), "provisional: lateral movement not established")
    exfil, exfil_ids = phase_text(("collection", "exfiltration"), "provisional: data access or exfiltration not established")
    confirmed = (
        "Confirmed technical compromise is supported by the cited local evidence."
        if str((view.get("posture") or {}).get("breach_status") or "").lower() == "confirmed"
        else "provisional: confirmed impact not established"
    )
    decisions = [
        str(item.get("title") or item.get("decision") or "")
        for item in view.get("immediate_decisions") or [] if isinstance(item, dict)
    ][:3]
    citations = {
        "what_happened": summary_ids,
        "entry_point": entry_ids,
        "persistence": persistence_ids,
        "lateral_movement": lateral_ids,
        "data_access_or_exfiltration": exfil_ids,
    }
    if not confirmed.startswith("provisional"):
        citations["confirmed_impact"] = summary_ids
    return {
        "headline": summary.get("headline") or "Evidence-backed case projection",
        "what_happened": summary.get("what_happened") or "provisional: insufficient evidence",
        "confirmed_impact": confirmed,
        "suspected_impact": "provisional: business impact requires a signed CMDB mapping",
        "entry_point": entry,
        "persistence": persistence,
        "lateral_movement": lateral,
        "data_access_or_exfiltration": exfil,
        "alternative_hypotheses": list(view.get("coverage_gaps") or []),
        "three_immediate_decisions": decisions,
        "coverage_gaps": list(view.get("coverage_gaps") or []),
        "overall_confidence": (view.get("posture") or {}).get("evidence_confidence"),
        "evidence_ids_by_field": citations,
        "generated_by": "deterministic_case_projection",
    }


@router.post("/api/v1/assessments/{assessment_id}/model-runs")
async def create_model_run(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> JSONResponse:
    tenant_id = _tenant(request, auth)
    body = await request.json()
    provider = str(body.get("provider") or "").strip().lower()
    if body.get("as_known_at"):
        raise HTTPException(409, "historical_model_runs_require_versioned_model_input_support")
    model = str(body.get("model") or "").strip()
    mode = str(body.get("mode") or "manual")
    if not provider or not model:
        raise HTTPException(status_code=422, detail="provider_and_model_required")
    view = await _load_case(assessment_id, tenant_id)
    partitions = [item for item in view.get("case_partitions") or [] if item.get("status") != "background"]
    truth_receipt = None
    truth_evaluation = None
    truth_fixture = None
    evidence_truth_receipt = None
    expected_evidence_ids: list[str] = []
    requested_truth_scenario = str(body.get("truth_scenario") or "").strip()
    truth_scenario = requested_truth_scenario or str(view.get("_acceptance_truth_scenario") or "")
    if truth_scenario:
        from src.core.acceptance_truth import evaluate_assessment_truth, load_truth_fixture

        try:
            truth_fixture, truth_receipt = load_truth_fixture(
                truth_scenario, caller_requested=bool(requested_truth_scenario),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        truth_evaluation = evaluate_assessment_truth(partitions, truth_fixture)
    requested_case_id = str(body.get("case_id") or "").strip()
    if len(partitions) > 1 and not requested_case_id:
        raise HTTPException(status_code=409, detail="case_id_required_for_multi_case_assessment")
    partition = None
    if requested_case_id or len(partitions) == 1:
        selected_id = requested_case_id or str(partitions[0].get("case_id"))
        partition = next((item for item in partitions if str(item.get("case_id")) == selected_id), None)
        if partition is None:
            raise HTTPException(status_code=404, detail="Case partition not found")
        view = _scope_view_to_partition(view, partition)
    if truth_fixture:
        from src.core.acceptance_truth import resolve_evidence_labels

        expected_evidence_ids, evidence_truth_receipt = resolve_evidence_labels(
            truth_fixture,
            [item for item in (view.get("evidence") or {}).get("rows") or [] if isinstance(item, dict)],
            scenario=truth_scenario,
            fixture_sha256=str((truth_receipt or {}).get("sha256") or ""),
        )
    external_allowed = bool(body.get("external_allowed"))
    from src.core.model_provider_registry import runtime_provider_config
    from src.core.model_run_store import ModelRunStore, run_case_model

    try:
        if provider == "deterministic":
            text = json.dumps(_deterministic_narration(view), ensure_ascii=False, default=str)
            meta = {"latency_ms": 0, "usage": {"prompt_tokens": 0, "completion_tokens": 0}}
        else:
            text, meta = await asyncio.to_thread(
                run_case_model,
                provider,
                model,
                _prompt(view),
                external_allowed=external_allowed,
                provider_config=runtime_provider_config(provider),
            )
        try:
            output: Any = json.loads(text)
        except Exception as parse_exc:
            # One bounded checker/repair pass. Preserve both attempts in the
            # immutable run; never silently accept repaired prose as evidence.
            repair_prompt = (
                "Repair the following incomplete or invalid JSON. Return one compact valid JSON object only. "
                "Preserve supplied evidence IDs exactly, remove unfinished fields, and do not add facts.\n"
                + text[:12000]
            )
            repair_text = ""
            repair_meta: dict[str, Any] = {}
            try:
                repair_text, repair_meta = await asyncio.to_thread(
                    run_case_model, provider, model, repair_prompt,
                    external_allowed=external_allowed,
                    provider_config=runtime_provider_config(provider),
                )
                output = json.loads(repair_text)
                meta["json_repair"] = {
                    "attempted": True, "succeeded": True,
                    "initial_error": type(parse_exc).__name__,
                    "latency_ms": repair_meta.get("latency_ms"),
                }
            except Exception as repair_exc:
                output = {
                    "raw_text": text,
                    "repair_raw_text": repair_text,
                    "parse_error": "provider_did_not_return_valid_json",
                }
                meta["json_repair"] = {
                    "attempted": True, "succeeded": False,
                    "initial_error": type(parse_exc).__name__,
                    "repair_error": type(repair_exc).__name__,
                    "latency_ms": repair_meta.get("latency_ms"),
                }
        from src.core.accuracy_loop import AccuracyLoop
        from src.core.agent_harness import SessionLog
        from src.core.model_evaluation import evaluate_model_output

        run_id = f"run-{uuid.uuid4().hex[:16]}"
        evaluation = evaluate_model_output(output, view, latency_ms=meta.get("latency_ms"))
        if truth_evaluation:
            evaluation.update({
                "must_detect": truth_evaluation.get("must_detect"),
                "must_separate": truth_evaluation.get("must_separate"),
                "must_suppress": truth_evaluation.get("must_suppress"),
                "role_attribution": truth_evaluation.get("role_attribution"),
                "acceptance_truth_status": "attached",
            })
        initial_output = output
        initial_evaluation = dict(evaluation)
        corrective_run: dict[str, Any] = {
            "triggered": False,
            "changed_evidence_set": False,
            "accepted": False,
        }
        needs_correction = (
            float(evaluation.get("attribution_quality") or 0) < 0.75
            or float(evaluation.get("evidence_recall") or 0) < 0.60
            or float(evaluation.get("unsupported_claim_rate") or 0) > 0.10
        )
        if provider != "deterministic" and needs_correction and body.get("corrective_retrieval", True):
            from src.api.ingest_endpoints import _compile_case_evidence_pack

            query = _corrective_query(output, evaluation, view)
            pack = await _compile_case_evidence_pack(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                requested_case_id=str(partition.get("case_id")) if partition else None,
                body={
                    "query": query,
                    "identifiers": [
                        str(item.get("entity") or item.get("entity_id"))
                        for item in (view.get("entity_roles") or view.get("roles") or [])
                        if isinstance(item, dict) and (item.get("entity") or item.get("entity_id"))
                    ],
                    "required_sensors": list(view.get("source_domains") or []),
                    "limit": int(body.get("corrective_limit") or 120),
                    "max_hops": 3,
                    "expected_evidence_ids": expected_evidence_ids,
                },
            )
            initial_ids = set(evaluation.get("support_ids") or [])
            corrected_rows = [
                {"id": item.get("evidence_id") or item.get("record_id")}
                for item in [*(pack.get("case_evidence") or []), *(pack.get("corrective_evidence") or [])]
                if item.get("evidence_id") or item.get("record_id")
            ]
            corrected_view = dict(view)
            corrected_view["evidence"] = {"rows": [*((view.get("evidence") or {}).get("rows") or []), *corrected_rows]}
            changed_evidence_set = bool({row["id"] for row in corrected_rows if row.get("id")} - initial_ids)
            correction_prompt = (
                _prompt(view)
                + "\nCORRECTIVE RETRIEVAL QUERY:\n" + query
                + "\nEVIDENCE PACK (local evidence is eligible; prior cases remain context only):\n"
                + json.dumps({
                    "case_evidence": (pack.get("case_evidence") or [])[:80],
                    "corrective_evidence": (pack.get("corrective_evidence") or [])[:40],
                    "contradicting_evidence": (pack.get("contradicting_evidence") or [])[:40],
                    "gaps": pack.get("gaps") or [],
                    "retrieval_trace": pack.get("retrieval_trace") or [],
                }, ensure_ascii=False, default=str)[:60000]
                + "\nRevise the JSON. Remove unsupported claims, explicitly describe contradictions/gaps, and cite only supplied evidence IDs."
            )
            if not changed_evidence_set:
                corrective_run = {
                    "triggered": True, "query": query, "pack_id": pack.get("pack_id"),
                    "pack_hash": pack.get("content_hash"), "changed_evidence_set": False,
                    "accepted": False, "abstained": True,
                    "abstention_reason": "corrective_retrieval_added_no_new_eligible_evidence",
                    "retrieval_trace": pack.get("retrieval_trace") or [],
                    "acceptance": pack.get("corrective_acceptance") or {},
                }
            else:
                correction_text, correction_meta = await asyncio.to_thread(
                    run_case_model, provider, model, correction_prompt,
                    external_allowed=external_allowed,
                    provider_config=runtime_provider_config(provider),
                )
                try:
                    correction_output = json.loads(correction_text)
                    correction_evaluation = evaluate_model_output(
                        correction_output, corrected_view, latency_ms=correction_meta.get("latency_ms"),
                    )
                    if truth_evaluation:
                        correction_evaluation.update({
                            "must_detect": truth_evaluation.get("must_detect"),
                            "must_separate": truth_evaluation.get("must_separate"),
                            "must_suppress": truth_evaluation.get("must_suppress"),
                            "role_attribution": truth_evaluation.get("role_attribution"),
                            "acceptance_truth_status": "attached",
                        })
                    accepted = _correction_improves(evaluation, correction_evaluation)
                    if accepted:
                        output, evaluation = correction_output, correction_evaluation
                    corrective_run = {
                        "triggered": True,
                        "query": query,
                        "pack_id": pack.get("pack_id"),
                        "pack_hash": pack.get("content_hash"),
                        "changed_evidence_set": True,
                        "retrieval_trace": pack.get("retrieval_trace") or [],
                        "initial_evaluation": initial_evaluation,
                        "candidate_evaluation": correction_evaluation,
                        "accepted": accepted, "abstained": not accepted,
                        "abstention_reason": None if accepted else "corrected_output_did_not_improve_grounding_metrics",
                        "acceptance": pack.get("corrective_acceptance") or {},
                        "latency_ms": correction_meta.get("latency_ms"),
                    }
                except Exception as exc:
                    corrective_run = {
                        "triggered": True, "query": query, "pack_id": pack.get("pack_id"),
                        "pack_hash": pack.get("content_hash"), "changed_evidence_set": True,
                        "accepted": False, "abstained": True,
                        "abstention_reason": "corrected_output_invalid",
                        "failure": type(exc).__name__,
                    }
        from src.core.model_escalation import decide_frontier_escalation

        escalation = decide_frontier_escalation(
            {
                **evaluation,
                "case_scoped": partition is not None,
                "case_partition_count": len(partitions) or 1,
            },
            external_approved=external_allowed,
        )
        loop = AccuracyLoop(SessionLog(), max_iterations=2)
        loop_result = await asyncio.to_thread(
            loop.run,
            tenant_id=tenant_id,
            case_id=assessment_id,
            session_id=f"model-{run_id}",
            evidence_pack={
                "pack_id": corrective_run.get("pack_id") or (view.get("report_context") or {}).get("evidence_pack_hash"),
                "content_hash": corrective_run.get("pack_hash") or (view.get("report_context") or {}).get("evidence_pack_hash"),
            },
            maker=lambda _pack, _feedback: output if isinstance(output, dict) else {"raw_text": str(output)},
            checker=lambda _claim, _pack: evaluation,
            critic=lambda _claim, verification: {"required_corrections": verification.get("gaps") or []},
        )
        record = await asyncio.to_thread(
            ModelRunStore().create,
            tenant_id,
            assessment_id,
            {
                "run_id": run_id,
                "mode": mode,
                "provider": provider,
                "model": model,
                "external_data_transfer": provider in {"openai", "anthropic"},
                "external_approved": external_allowed,
                "evidence_pack_hash": corrective_run.get("pack_hash") or (view.get("report_context") or {}).get("evidence_pack_hash"),
                "prompt_version": "janusec.case-review/v1",
                "selection": {
                    "scope": "case" if partition else "assessment",
                    "case_id": partition.get("case_id") if partition else None,
                    "case_partition_hash": partition.get("content_hash") if partition else None,
                    "case_partition_count": len(partitions) or 1,
                    "provider": provider,
                    "model": model,
                    "mode": mode,
                    "external_allowed": external_allowed,
                    "immutable": True,
                },
                "output": output,
                "initial_output": initial_output if corrective_run.get("triggered") else None,
                "accuracy_evaluation": evaluation,
                "acceptance_truth_receipt": truth_receipt,
                "acceptance_truth_evaluation": truth_evaluation,
                "evidence_truth_receipt": evidence_truth_receipt,
                "accuracy_loop": {
                    "session_id": f"model-{run_id}",
                    "iterations": loop_result.iterations,
                    "stop_reason": loop_result.stop_reason,
                    "receipt_hash": loop_result.receipt_hash,
                },
                "corrective_retrieval": corrective_run,
                "frontier_escalation": escalation,
                **meta,
            },
        )
        return JSONResponse(content=record, status_code=201)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:
        failed_run_id = f"run-{uuid.uuid4().hex[:16]}"
        try:
            from src.core.model_run_store import ModelRunStore

            await asyncio.to_thread(
                ModelRunStore().create,
                tenant_id,
                assessment_id,
                {
                    "run_id": failed_run_id,
                    "status": "failed",
                    "mode": mode,
                    "provider": provider,
                    "model": model,
                    "external_data_transfer": provider in {"openai", "anthropic"},
                    "external_approved": external_allowed,
                    "acceptance_truth_receipt": truth_receipt,
                    "acceptance_truth_evaluation": truth_evaluation,
                    "evidence_truth_receipt": evidence_truth_receipt,
                    "selection": {
                        "scope": "case" if partition else "assessment",
                        "case_id": partition.get("case_id") if partition else None,
                        "case_partition_hash": partition.get("content_hash") if partition else None,
                        "immutable": True,
                    },
                    "failure": {"type": type(exc).__name__, "message": str(exc)[:240]},
                },
            )
        except Exception:
            pass
        raise HTTPException(
            status_code=502,
            detail={"error": "model_run_failed", "run_id": failed_run_id, "failure_type": type(exc).__name__},
        ) from exc


async def _execute_queued_model_job(
    *, assessment_id: str, tenant_id: str, request: Request, auth: object,
    job_id: str, hard_budget_seconds: float,
) -> None:
    from src.core.async_model_runs import AsyncModelRunStore

    store = AsyncModelRunStore()
    started_at = time.time()
    try:
        store.transition(
            tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
            status="running",
            details={"started_at": started_at, "generation_concurrency": _GENERATION_CONCURRENCY},
        )
        async with _GENERATION_SEMAPHORE:
            response = await asyncio.wait_for(
                create_model_run(assessment_id, request, auth),
                timeout=hard_budget_seconds,
            )
        record = json.loads(bytes(response.body).decode("utf-8"))
        corrective = record.get("corrective_retrieval") if isinstance(record, dict) else {}
        if isinstance(corrective, dict) and corrective.get("triggered"):
            store.transition(
                tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
                status="correcting",
                details={
                    "pack_id": corrective.get("pack_id"),
                    "changed_evidence_set": bool(corrective.get("changed_evidence_set")),
                    "accepted": bool(corrective.get("accepted")),
                    "abstained": bool(corrective.get("abstained")),
                },
            )
        escalation = record.get("frontier_escalation") if isinstance(record, dict) else {}
        should_escalate = isinstance(escalation, dict) and bool(
            escalation.get("escalate") or escalation.get("required") or escalation.get("triggered")
        )
        if should_escalate:
            store.transition(
                tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
                status="escalating", details={"policy": escalation},
            )
        store.transition(
            tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
            status="completed",
            details={
                "run_id": record.get("run_id") if isinstance(record, dict) else None,
                "record_hash": record.get("record_hash") if isinstance(record, dict) else None,
                "completed_at": time.time(), "elapsed_seconds": round(time.time() - started_at, 3),
            },
        )
    except asyncio.TimeoutError:
        store.transition(
            tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
            status="budget_exhausted",
            details={
                "hard_budget_seconds": hard_budget_seconds,
                "elapsed_seconds": round(time.time() - started_at, 3),
            },
        )
    except asyncio.CancelledError:
        try:
            store.transition(
                tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
                status="cancelled",
                details={"cancelled_at": time.time(), "elapsed_seconds": round(time.time() - started_at, 3)},
            )
        finally:
            raise
    except Exception as exc:
        store.transition(
            tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
            status="failed",
            details={
                "failure_type": type(exc).__name__, "message": str(exc)[:240],
                "elapsed_seconds": round(time.time() - started_at, 3),
            },
        )
    finally:
        _MODEL_JOB_TASKS.pop(job_id, None)


@router.post("/api/v1/assessments/{assessment_id}/model-jobs")
async def queue_model_run(
    assessment_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> JSONResponse:
    """Queue model work without blocking ingestion, embeddings, or the browser."""

    tenant_id = _tenant(request, auth)
    body = await request.json()
    # Ensure ownership and provider input are rejected before a durable job is created.
    await _load_case(assessment_id, tenant_id)
    if not str(body.get("provider") or "").strip() or not str(body.get("model") or "").strip():
        raise HTTPException(status_code=422, detail="provider_and_model_required")
    default_budget = float(os.getenv("MODEL_RUN_HARD_BUDGET_SECONDS", "300") or 300)
    maximum_budget = float(os.getenv("MODEL_RUN_MAX_BUDGET_SECONDS", "1800") or 1800)
    hard_budget = max(1.0, min(float(body.get("hard_budget_seconds") or default_budget), maximum_budget))
    from src.core.async_model_runs import AsyncModelRunStore

    job = await asyncio.to_thread(
        AsyncModelRunStore().create,
        tenant_id=tenant_id, assessment_id=assessment_id,
        request={key: value for key, value in body.items() if key not in {"api_key", "token", "secret"}},
        hard_budget_seconds=hard_budget,
    )
    task = asyncio.create_task(
        _execute_queued_model_job(
            assessment_id=assessment_id, tenant_id=tenant_id, request=request,
            auth=auth, job_id=job["job_id"], hard_budget_seconds=hard_budget,
        ),
        name=f"janusec-{job['job_id']}",
    )
    _MODEL_JOB_TASKS[job["job_id"]] = task
    return JSONResponse(content={
        **job,
        "budgets": {
            "hard_budget_seconds": hard_budget,
            "generation_concurrency": _GENERATION_CONCURRENCY,
            "embedding_concurrency": max(1, int(os.getenv("MODEL_EMBEDDING_CONCURRENCY", "1") or 1)),
        },
    }, status_code=202)


@router.get("/api/v1/assessments/{assessment_id}/model-jobs/{job_id}")
async def get_model_job(
    assessment_id: str, job_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> JSONResponse:
    tenant_id = _tenant(request, auth)
    await _load_case(assessment_id, tenant_id)
    from src.core.async_model_runs import AsyncModelRunStore

    try:
        job = await asyncio.to_thread(
            AsyncModelRunStore().load,
            tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="model_job_not_found") from exc
    return JSONResponse(content=job)


@router.delete("/api/v1/assessments/{assessment_id}/model-jobs/{job_id}")
async def cancel_model_job(
    assessment_id: str, job_id: str, request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> JSONResponse:
    tenant_id = _tenant(request, auth)
    await _load_case(assessment_id, tenant_id)
    from src.core.async_model_runs import AsyncModelRunStore

    try:
        job = await asyncio.to_thread(
            AsyncModelRunStore().load,
            tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="model_job_not_found") from exc
    if job.get("terminal"):
        return JSONResponse(content=job)
    task = _MODEL_JOB_TASKS.get(job_id)
    if task is None:
        # The worker was restarted. Record the loss explicitly instead of
        # leaving a durable job looking active forever.
        job = await asyncio.to_thread(
            AsyncModelRunStore().transition,
            tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
            status="cancelled", details={"reason": "worker_not_active"},
        )
    else:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        job = await asyncio.to_thread(
            AsyncModelRunStore().load,
            tenant_id=tenant_id, assessment_id=assessment_id, job_id=job_id,
        )
    return JSONResponse(content=job)


@router.get("/api/v1/assessments/{assessment_id}/model-runs")
async def list_model_runs(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    tenant_id = _tenant(request, auth)
    await _load_case(assessment_id, tenant_id)
    from src.core.model_run_store import ModelRunStore

    return {"assessment_id": assessment_id, "runs": await asyncio.to_thread(ModelRunStore().list, tenant_id, assessment_id)}


@router.post("/api/v1/assessments/{assessment_id}/model-runs/compare")
async def compare_model_runs(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
) -> dict[str, Any]:
    tenant_id = _tenant(request, auth)
    await _load_case(assessment_id, tenant_id)
    body = await request.json()
    requested = set(str(value) for value in (body.get("run_ids") or []))
    from src.core.model_run_store import ModelRunStore

    runs = await asyncio.to_thread(ModelRunStore().list, tenant_id, assessment_id)
    selected = [run for run in runs if not requested or run.get("run_id") in requested]
    fields = sorted({field for run in selected for field in ((run.get("output") or {}).keys() if isinstance(run.get("output"), dict) else [])})
    from src.core.model_escalation import decide_frontier_escalation

    return {
        "assessment_id": assessment_id,
        "runs": [{"run_id": run.get("run_id"), "provider": run.get("provider"), "model": run.get("model"), "record_hash": run.get("record_hash")} for run in selected],
        "comparison": {field: {str(run.get("run_id")): (run.get("output") or {}).get(field) for run in selected} for field in fields},
        "accuracy_metrics": {
            str(run.get("run_id")): run.get("accuracy_evaluation") or {}
            for run in selected
        },
        "frontier_escalation": {
            str(run.get("run_id")): decide_frontier_escalation(
                {
                    **(run.get("accuracy_evaluation") or {}),
                    "case_scoped": (run.get("selection") or {}).get("scope") == "case",
                    "case_partition_count": (run.get("selection") or {}).get("case_partition_count", 1),
                },
                external_approved=bool((run.get("selection") or {}).get("external_allowed")),
            )
            for run in selected
        },
        "overwrites_original_assessment": False,
    }


@router.get("/api/v1/assessments/{assessment_id}/grc-action-pack")
async def grc_action_pack(
    assessment_id: str,
    request: Request,
    auth: Annotated[object, Depends(require_api_key)],
    format: str = "html",
    case_id: str | None = None,
    as_known_at: str | None = None,
    customer_profile_id: str | None = None,
):
    tenant_id = _tenant(request, auth)
    import json
    from src.api.ingest_endpoints import case_view
    response = await case_view(assessment_id, request, auth, case_id=case_id, as_known_at=as_known_at)
    view = json.loads(response.body)
    if format == "oscal":
        import hashlib
        import os
        from pathlib import Path
        import re
        from src.reporting.oscal_export import export_case_evidence
        if not customer_profile_id or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", customer_profile_id):
            raise HTTPException(422, "customer_profile_id_required")
        root = Path(os.getenv("JANUSEC_CUSTOMER_PROFILE_DIR", "config/customer_profiles")).resolve()
        path = Path(storage_path(storage_path(root, hashlib.sha256(tenant_id.encode()).hexdigest()), customer_profile_id + ".json"))
        if not path.resolve().is_relative_to(root) or not path.is_file():
            raise HTTPException(404, "customer_profile_not_found")
        try:
            profile = json.loads(path.read_text(encoding="utf-8"))
            return JSONResponse(content=export_case_evidence(view, profile, tenant_id=tenant_id))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    if format == "json":
        return JSONResponse(content=view)
    if format != "html":
        raise HTTPException(status_code=400, detail="supported_formats:html,json,oscal")
    from src.reporting.grc_action_pack import render_grc_action_pack

    return HTMLResponse(render_grc_action_pack(view), headers={"Content-Disposition": f'inline; filename="{assessment_id}-grc-action-pack.html"'})


__all__ = ["router"]
