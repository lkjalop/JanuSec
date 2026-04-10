from __future__ import annotations

import re
import time
from typing import Any


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _bounded_unique(values: list[Any] | tuple[Any, ...] | None, limit: int) -> list[str]:
    seen: list[str] = []
    for value in values or []:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.append(text)
        if len(seen) >= limit:
            break
    return seen


def _normalize_lead_entries(values: list[Any] | tuple[Any, ...] | None, *, category: str, default_availability: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for raw in values or []:
        if isinstance(raw, dict):
            lead = str(raw.get("lead") or raw.get("text") or "").strip()
            if not lead:
                continue
            item = dict(raw)
            item.setdefault("lead", lead)
            item.setdefault("category", category)
            item["expected_information_gain"] = round(_safe_float(item.get("expected_information_gain"), 0.54), 3)
            item["artifact_availability"] = str(item.get("artifact_availability") or default_availability)
            item.setdefault("why_it_matters", f"{lead} helps {category.replace('_', ' ')} for this cluster.")
            entries.append(item)
        else:
            lead = str(raw or "").strip()
            if not lead:
                continue
            entries.append(
                {
                    "lead": lead,
                    "category": category,
                    "expected_information_gain": 0.54,
                    "artifact_availability": default_availability,
                    "why_it_matters": f"{lead} helps {category.replace('_', ' ')} for this cluster.",
                }
            )
    return entries[:6]


def _normalize_leads(leads: dict[str, Any] | None, missing_telemetry: list[str], source_reliability: list[dict[str, Any]] | None) -> dict[str, Any]:
    source_reliability = source_reliability or []
    leads = dict(leads or {})
    next_best = _normalize_lead_entries(
        list(leads.get("next_best") or []) + list(leads.get("next_best_details") or []),
        category="next_best",
        default_availability="available_now",
    )
    confirmation = _normalize_lead_entries(
        list(leads.get("confirmation") or []) + list(leads.get("confirmation_details") or []),
        category="confirmation",
        default_availability="available_now",
    )
    denial = _normalize_lead_entries(
        list(leads.get("denial") or []) + list(leads.get("denial_details") or []),
        category="denial",
        default_availability="requires_owner_validation",
    )
    scope_expansion = _normalize_lead_entries(
        leads.get("scope_expansion") or leads.get("scope_expansion_details"),
        category="scope_expansion",
        default_availability="requires_live_pull",
    )
    high_value_missing = _bounded_unique(leads.get("high_value_missing_telemetry") or missing_telemetry, 4)
    closure_blockers = _bounded_unique(
        leads.get("closure_blockers")
        or high_value_missing
        or [item.get("source") for item in source_reliability[:2] if item.get("type") == "heuristic"],
        4,
    )
    normalized = {
        "next_best": [item["lead"] for item in next_best],
        "confirmation": [item["lead"] for item in confirmation],
        "denial": [item["lead"] for item in denial],
        "high_value_missing_telemetry": high_value_missing,
        "next_best_details": next_best,
        "confirmation_details": confirmation,
        "denial_details": denial,
        "scope_expansion_details": scope_expansion,
        "closure_blockers": closure_blockers,
        "lead_outcomes": list(leads.get("lead_outcomes") or [])[:12],
    }
    return normalized


def _default_close_conditions(*, summary: dict[str, Any], leads: dict[str, Any], missing_telemetry: list[str]) -> dict[str, list[str]]:
    hypothesis = str(summary.get("top_hypothesis") or "shared cluster path").strip()
    confirmation = list(leads.get("confirmation") or [])
    denial = list(leads.get("denial") or [])
    blockers = list(leads.get("closure_blockers") or [])
    missing = missing_telemetry[:3]
    return {
        "soc_close_conditions": [
            "Containment is confirmed for the affected identities, hosts, or cloud resources.",
            confirmation[0] if confirmation else f"Validate the highest-confidence pivot for {hypothesis}.",
            blockers[0] if blockers else "Record whether additional telemetry is still required before closure.",
        ],
        "hunter_close_conditions": [
            denial[0] if denial else "Rule out the strongest benign explanation before closing the hunt.",
            "Expand or deny adjacent pivots until no higher-value leads remain.",
            missing[0] if missing else "Document why no further hunt pivots are required.",
        ],
        "forensics_close_conditions": [
            "Preserve the primary artifacts and custody trail before evidence ages out.",
            missing[0] if missing else "Collect the highest-value missing telemetry before finalizing the timeline.",
            "Document whether delayed or backfilled evidence changed the final verdict.",
        ],
    }


def infer_reasoning_budget(*, reasoning_mode: str, contradiction_count: int, analyst_delta: float, cluster_size: int) -> str:
    mode = str(reasoning_mode or "cheap").lower()
    if mode == "deep" or contradiction_count >= 2 or analyst_delta >= 0.25 or cluster_size >= 4:
        return "deep"
    if mode == "standard" or contradiction_count == 1 or cluster_size >= 2:
        return "standard"
    return "cheap"


def build_reasoning_trace(
    *,
    generated_ts: int,
    trigger_reason: str,
    routing_score: float,
    corroboration_confidence: float,
    top_hypothesis: str,
    analyst_state: dict[str, Any] | None,
    corroboration_status: str,
    corroboration_verdict: str,
    prior_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    analyst_state = analyst_state or {}
    state_before_review = {
        "ts": (prior_state or {}).get("generated_ts") or generated_ts,
        "trigger": (prior_state or {}).get("trigger_reason") or trigger_reason,
        "top_hypothesis": ((prior_state or {}).get("summary") or {}).get("top_hypothesis") or top_hypothesis,
        "routing_score": round(_safe_float((prior_state or {}).get("routing_score"), routing_score), 3),
    }
    state_after_review = {
        "ts": generated_ts,
        "review_status": analyst_state.get("review_status") or "unreviewed",
        "hypothesis": analyst_state.get("hypothesis") or top_hypothesis,
        "factors_added": _bounded_unique(analyst_state.get("factors_added"), 12),
        "factors_removed": _bounded_unique(analyst_state.get("factors_removed"), 12),
        "confidence_override": analyst_state.get("confidence_override"),
        "disposition_delta": round(_safe_float(analyst_state.get("disposition_delta")), 3),
    }
    state_after_corroboration = {
        "ts": generated_ts if corroboration_status == "completed" else None,
        "status": corroboration_status,
        "verdict": corroboration_verdict,
        "confidence": round(_safe_float(corroboration_confidence), 3),
    }
    return {
        "state_before_review": state_before_review,
        "state_after_review": state_after_review,
        "state_after_corroboration": state_after_corroboration,
        "verdict_delta": {
            "from": round(_safe_float(state_before_review.get("routing_score")), 3),
            "to": round(_safe_float(corroboration_confidence), 3),
            "delta": round(_safe_float(corroboration_confidence) - _safe_float(state_before_review.get("routing_score")), 3),
        },
    }


def build_cluster_reasoning_state(
    *,
    assessment_id: str | None,
    cluster_id: str | None,
    session_id: str | None = None,
    version: str = "v1",
    generated_ts: int | None = None,
    trigger_reason: str,
    routing_mode: str,
    reasoning_mode: str,
    cluster_size: int,
    severity_score: float,
    graph_score: float,
    ewma_score: float,
    pattern_support_score: float,
    routing_score: float,
    analyst_state: dict[str, Any] | None,
    canonical_narrative: str,
    top_hypothesis: str,
    supporting_evidence: list[Any] | None = None,
    contradictions: list[Any] | None = None,
    missing_telemetry: list[Any] | None = None,
    recommended_actions: list[Any] | None = None,
    corroboration_status: str = "deferred",
    corroboration_verdict: str = "needs_more_evidence",
    corroboration_confidence: float | None = None,
    corroboration_run_ts: int | None = None,
    evidence_used: list[Any] | None = None,
    alt_hypotheses: list[dict[str, Any]] | None = None,
    claims: list[dict[str, Any]] | None = None,
    leads: dict[str, Any] | None = None,
    reasoning_trace: dict[str, Any] | None = None,
    source_reliability: list[dict[str, Any]] | None = None,
    what_would_flip: list[Any] | None = None,
    disconfirming_evidence: list[Any] | None = None,
    persona_seed_claims: list[Any] | None = None,
    persona_seed_actions: list[Any] | None = None,
    persona_seed_missing_telemetry: list[Any] | None = None,
    temporal_rag_sources: list[Any] | None = None,
    shared_pivots: list[Any] | None = None,
    provider_context: dict[str, Any] | None = None,
    prior_state: dict[str, Any] | None = None,
    evidence_row_indices: list[int] | None = None,
    close_conditions: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    generated_ts = int(generated_ts or time.time())
    supporting_evidence = _bounded_unique(supporting_evidence, 8)
    contradictions = _bounded_unique(contradictions, 6)
    missing_telemetry = _bounded_unique(missing_telemetry, 8)
    recommended_actions = _bounded_unique(recommended_actions, 6)
    evidence_used = _bounded_unique(evidence_used, 8)
    temporal_rag_sources = _bounded_unique(temporal_rag_sources, 8)
    what_would_flip = _bounded_unique(what_would_flip, 5)
    disconfirming_evidence = _bounded_unique(disconfirming_evidence, 6)
    persona_seed_claims = _bounded_unique(persona_seed_claims, 6)
    persona_seed_actions = _bounded_unique(persona_seed_actions, 6)
    persona_seed_missing_telemetry = _bounded_unique(persona_seed_missing_telemetry, 5)
    shared_pivots = _bounded_unique(shared_pivots, 8)
    cluster_size = max(0, int(cluster_size or 0))
    routing_score = round(_safe_float(routing_score), 3)
    corroboration_confidence = round(_safe_float(corroboration_confidence, routing_score), 3)
    contradiction_count = len(contradictions) + len(disconfirming_evidence)
    reasoning_budget = infer_reasoning_budget(
        reasoning_mode=reasoning_mode,
        contradiction_count=contradiction_count,
        analyst_delta=_safe_float((analyst_state or {}).get("disposition_delta")),
        cluster_size=cluster_size,
    )
    if reasoning_trace is None:
        reasoning_trace = build_reasoning_trace(
            generated_ts=generated_ts,
            trigger_reason=trigger_reason,
            routing_score=routing_score,
            corroboration_confidence=corroboration_confidence,
            top_hypothesis=top_hypothesis,
            analyst_state=analyst_state,
            corroboration_status=corroboration_status,
            corroboration_verdict=corroboration_verdict,
            prior_state=prior_state,
        )
    leads = _normalize_leads(leads, missing_telemetry, source_reliability)
    close_conditions = dict(close_conditions or _default_close_conditions(summary={
        "top_hypothesis": top_hypothesis,
    }, leads=leads, missing_telemetry=missing_telemetry))
    provider_context = dict(provider_context or {})
    provider_context.setdefault("evidence_age", {
        "valid_time": provider_context.get("valid_time"),
        "transaction_time": provider_context.get("transaction_time"),
        "backfill_changed_verdict": bool((reasoning_trace.get("verdict_delta") or {}).get("delta")) and bool(provider_context.get("backfill_observed")),
    })
    state = {
        "assessment_id": assessment_id,
        "cluster_id": cluster_id,
        "session_id": session_id,
        "version": version,
        "generated_ts": generated_ts,
        "trigger_reason": trigger_reason,
        "routing_mode": routing_mode,
        "reasoning_mode": reasoning_mode,
        "reasoning_budget": reasoning_budget,
        "cluster_size": cluster_size,
        "severity_score": round(_safe_float(severity_score), 3),
        "graph_score": round(_safe_float(graph_score), 3),
        "ewma_score": round(_safe_float(ewma_score), 3),
        "pattern_support_score": round(_safe_float(pattern_support_score), 3),
        "routing_score": routing_score,
        "analyst_state": analyst_state or {},
        "summary": {
            "canonical_narrative": canonical_narrative,
            "top_hypothesis": top_hypothesis,
            "supporting_evidence": supporting_evidence,
            "contradictions": contradictions,
            "missing_telemetry": missing_telemetry,
            "recommended_actions": recommended_actions,
        },
        "corroboration": {
            "status": corroboration_status,
            "run_ts": corroboration_run_ts,
            "verdict": corroboration_verdict,
            "confidence": corroboration_confidence,
            "delta_from_initial": round(corroboration_confidence - routing_score, 3),
            "evidence_used": evidence_used,
        },
        "alt_hypotheses": alt_hypotheses or [],
        "claims": claims or [],
        "leads": leads,
        "reasoning_trace": reasoning_trace,
        "source_reliability": source_reliability or [],
        "what_would_flip": what_would_flip,
        "disconfirming_evidence": disconfirming_evidence,
        "temporal_rag_sources": temporal_rag_sources,
        "shared_pivots": shared_pivots,
        "persona_views_seed": {
            "claims": persona_seed_claims or [canonical_narrative, top_hypothesis],
            "action_candidates": persona_seed_actions or recommended_actions[:3],
            "missing_telemetry": persona_seed_missing_telemetry or missing_telemetry[:4],
        },
        "provider_context": provider_context or {},
        "evidence_row_indices": evidence_row_indices or [],
        "close_conditions": close_conditions,
    }
    if prior_state and isinstance(prior_state, dict):
        state["previous_generated_ts"] = prior_state.get("generated_ts")
    return state


def build_cluster_reasoning_root(
    *,
    assessment_id: str | None,
    session_id: str | None = None,
    version: str = "v1",
    generated_ts: int | None = None,
    cluster_states: list[dict[str, Any]] | None = None,
    preferred_cluster_id: str | None = None,
) -> dict[str, Any]:
    cluster_states = list(cluster_states or [])
    generated_ts = int(generated_ts or time.time())
    primary = None
    if preferred_cluster_id:
        primary = next((item for item in cluster_states if item.get("cluster_id") == preferred_cluster_id), None)
    if primary is None and cluster_states:
        primary = max(
            cluster_states,
            key=lambda item: (
                _safe_float(item.get("routing_score")),
                _safe_float(item.get("severity_score")),
                _safe_float(item.get("cluster_size")),
            ),
        )
    return {
        "assessment_id": assessment_id,
        "session_id": session_id,
        "version": version,
        "generated_ts": generated_ts,
        "primary_cluster_id": (primary or {}).get("cluster_id"),
        "cluster_states": cluster_states,
        "summary": (primary or {}).get("summary") or {},
        "corroboration": (primary or {}).get("corroboration") or {},
        "persona_views_seed": (primary or {}).get("persona_views_seed") or {},
        "routing_mode": (primary or {}).get("routing_mode"),
        "reasoning_mode": (primary or {}).get("reasoning_mode"),
        "reasoning_budget": (primary or {}).get("reasoning_budget"),
        "cluster_size": (primary or {}).get("cluster_size"),
        "severity_score": (primary or {}).get("severity_score"),
        "graph_score": (primary or {}).get("graph_score"),
        "ewma_score": (primary or {}).get("ewma_score"),
        "pattern_support_score": (primary or {}).get("pattern_support_score"),
        "routing_score": (primary or {}).get("routing_score"),
        "analyst_state": (primary or {}).get("analyst_state") or {},
        "temporal_rag_sources": (primary or {}).get("temporal_rag_sources") or [],
        "shared_pivots": (primary or {}).get("shared_pivots") or [],
        "alt_hypotheses": (primary or {}).get("alt_hypotheses") or [],
        "claims": (primary or {}).get("claims") or [],
        "leads": (primary or {}).get("leads") or {},
        "reasoning_trace": (primary or {}).get("reasoning_trace") or {},
        "source_reliability": (primary or {}).get("source_reliability") or [],
        "what_would_flip": (primary or {}).get("what_would_flip") or [],
        "disconfirming_evidence": (primary or {}).get("disconfirming_evidence") or [],
        "close_conditions": (primary or {}).get("close_conditions") or {},
        "provider_context": (primary or {}).get("provider_context") or {},
        "evidence_row_indices": (primary or {}).get("evidence_row_indices") or [],
    }


def compact_cluster_reasoning_state(state: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(state, dict):
        return {}
    return {
        "cluster_id": state.get("cluster_id"),
        "version": state.get("version"),
        "generated_ts": state.get("generated_ts"),
        "trigger_reason": state.get("trigger_reason"),
        "routing_mode": state.get("routing_mode"),
        "reasoning_mode": state.get("reasoning_mode"),
        "reasoning_budget": state.get("reasoning_budget"),
        "cluster_size": state.get("cluster_size"),
        "severity_score": state.get("severity_score"),
        "graph_score": state.get("graph_score"),
        "ewma_score": state.get("ewma_score"),
        "pattern_support_score": state.get("pattern_support_score"),
        "routing_score": state.get("routing_score"),
        "analyst_state": state.get("analyst_state") or {},
        "summary": {
            "canonical_narrative": ((state.get("summary") or {}).get("canonical_narrative")),
            "top_hypothesis": ((state.get("summary") or {}).get("top_hypothesis")),
            "recommended_actions": ((state.get("summary") or {}).get("recommended_actions") or [])[:3],
        },
        "corroboration": state.get("corroboration") or {},
        "persona_views_seed": state.get("persona_views_seed") or {},
        "alt_hypotheses": state.get("alt_hypotheses") or [],
        "claims": state.get("claims") or [],
        "leads": state.get("leads") or {},
        "reasoning_trace": state.get("reasoning_trace") or {},
        "source_reliability": state.get("source_reliability") or [],
        "what_would_flip": state.get("what_would_flip") or [],
        "disconfirming_evidence": state.get("disconfirming_evidence") or [],
        "temporal_rag_sources": state.get("temporal_rag_sources") or [],
        "shared_pivots": state.get("shared_pivots") or [],
        "provider_context": state.get("provider_context") or {},
        "evidence_row_indices": state.get("evidence_row_indices") or [],
        "close_conditions": state.get("close_conditions") or {},
    }


_GUIDED_NOTE_PATTERNS = {
    "hypothesis": re.compile(r"^\s*hypothesis\s*:\s*(.+)$", re.I),
    "confirm_or_deny": re.compile(r"^\s*(?:confirm|deny|defer|decision)\s*:\s*(.+)$", re.I),
    "factors_added": re.compile(r"^\s*(?:add|added|factors_added)\s*:\s*(.+)$", re.I),
    "factors_removed": re.compile(r"^\s*(?:remove|removed|factors_removed)\s*:\s*(.+)$", re.I),
    "requested_telemetry": re.compile(r"^\s*(?:telemetry|request|requested_telemetry)\s*:\s*(.+)$", re.I),
    "disposition_delta": re.compile(r"^\s*(?:delta|disposition_delta)\s*:\s*([-+]?\d*\.?\d+)\s*$", re.I),
}


def parse_guided_analyst_note(note: str | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "hypothesis": "",
        "confirm_or_deny": "",
        "factors_added": [],
        "factors_removed": [],
        "requested_telemetry": [],
        "disposition_delta": None,
    }
    if not note:
        return parsed
    for line in str(note).splitlines():
        text = line.strip()
        if not text:
            continue
        for key, pattern in _GUIDED_NOTE_PATTERNS.items():
            match = pattern.match(text)
            if not match:
                continue
            value = match.group(1).strip()
            if key == "hypothesis":
                parsed["hypothesis"] = value[:400]
            elif key == "confirm_or_deny":
                parsed["confirm_or_deny"] = value[:64].lower()
            elif key in {"factors_added", "factors_removed", "requested_telemetry"}:
                parsed[key] = _bounded_unique(re.split(r"[,;]", value), 12)
            elif key == "disposition_delta":
                parsed[key] = round(_safe_float(value), 3)
            break
    return parsed
