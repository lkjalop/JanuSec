"""
Router — orchestrates the Planner → Investigator → Verifier → Narrator loop.

Entry point: ``run_investigation(context, assessment_summary)``

The loop runs until:
  - No new findings AND no fetchable gaps → investigation complete
  - Budget exhausted (max_cycles, max_tokens, max_queries)
  - Human intervention required (all remaining leads need Zone 2/3 approval)
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Set

from src.agents.autonomy_gate import ScopeTracker, get_compliance_tags
from src.agents.investigator import investigate
from src.agents.narrator import narrate
from src.agents.planner import plan
from src.agents.types import (
    AgentCycle,
    Gap,
    InvestigationContext,
    InvestigationMemory,
    MemoryArtifact,
    ProposedAction,
    RejectionReason,
    VerifiedFinding,
)
from src.agents.session_store import InvestigationSessionStore
from src.agents.verifier import verify
from src.audit.logger import audit

LOGGER = logging.getLogger(__name__)


async def run_investigation(
    context: InvestigationContext,
    assessment_summary: Dict[str, Any],
    *,
    engagement_actors: Optional[Set[str]] = None,
    engagement_ips: Optional[Set[str]] = None,
    llm_client: Any = None,
    cluster_id: str = "",
    _resume_state: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Run the full agentic investigation loop.

    Returns a dict containing:
      - investigation_id
      - cycles: list of AgentCycle summaries
      - final_narrative
      - confidence
      - compliance_controls
      - proposed_actions: Zone 2/3 actions awaiting approval
      - gaps: unresolved data gaps
      - close_reason
      - tokens_used, queries_used
    """
    audit("investigation_start", investigation_id=context.investigation_id,
          assessment_id=context.assessment_id, tenant_id=context.tenant_id)

    scope = ScopeTracker(
        max_bytes=context.max_tokens * 4,
        max_queries=context.max_queries,
    )

    all_cycles: List[AgentCycle] = []
    all_verified: List[VerifiedFinding] = []
    all_proposed: List[ProposedAction] = []
    all_gaps: List[Gap] = []
    narrative = ""
    corrective_feedback: List[RejectionReason] = []
    total_tokens = 0
    total_queries = 0
    close_reason = "max_cycles"
    narration: Dict[str, Any] = {}
    kill_chain: list = []
    memory = InvestigationMemory()

    # Seed loop state from resume snapshot when provided (fix: resume actually resumes)
    if _resume_state:
        all_verified = _rebuild_verified_findings(_resume_state.get("all_verified", []))
        all_gaps = _rebuild_gaps(_resume_state.get("all_gaps", []))
        corrective_feedback = _rebuild_rejection_reasons(_resume_state.get("corrective_feedback", []))
        narrative = _resume_state.get("narrative", "")
        LOGGER.info(
            "Resume: seeded %d verified, %d gaps, %d feedback entries from prior state",
            len(all_verified), len(all_gaps), len(corrective_feedback),
        )

    session = InvestigationSessionStore(
        session_id=context.investigation_id,
        tenant_id=context.tenant_id,
        assessment_id=context.assessment_id,
        cluster_id=cluster_id,
    )

    for cycle_num in range(1, context.max_cycles + 1):
        LOGGER.info("=== Investigation %s — Cycle %d/%d ===",
                     context.investigation_id, cycle_num, context.max_cycles)

        # ── 1. PLAN ──────────────────────────────────────────────────────
        # Compute compressed prior at cycle 4+ (Compress primitive)
        compressed_prior = ""
        if cycle_num >= 4:
            compressed_prior = memory.compress(up_to_cycle=cycle_num - 1)

        investigation_plan = await plan(
            context,
            assessment_summary,
            previous_findings=all_verified[-20:] if all_verified else None,
            corrective_feedback=corrective_feedback[-20:] if corrective_feedback else None,
            gaps=all_gaps[-10:] if all_gaps else None,
            cycle=cycle_num,
            llm_client=llm_client,
            memory=memory,
            compressed_prior=compressed_prior,
        )

        if not investigation_plan.steps and not investigation_plan.gaps:
            close_reason = "no_more_leads"
            LOGGER.info("Planner returned empty plan — closing investigation")
            break

        # ── 2. INVESTIGATE ───────────────────────────────────────────────
        raw_findings, proposed_actions = await investigate(
            investigation_plan, context, scope=scope,
        )
        all_proposed.extend(proposed_actions)

        # ── 3. VERIFY ───────────────────────────────────────────────────
        verified, rejected, weak = verify(
            raw_findings,
            context,
            engagement_actors=engagement_actors,
            engagement_ips=engagement_ips,
            fp_patterns=corrective_feedback,
            gaps=investigation_plan.gaps,
        )
        all_verified.extend(verified)

        # Write primitive: persist new discoveries to InvestigationMemory
        memory.write_from_findings(verified, cycle=cycle_num)

        # Feed rejected reasons back into corrective feedback (structured)
        for rej in rejected:
            if rej.rejection_reason:
                corrective_feedback.append(rej.rejection_reason)

        # ── 3b. KILL CHAIN ──────────────────────────────────────────────
        from src.agents.kill_chain import extract_kill_chain
        kill_chain = extract_kill_chain(verified)

        # ── 4. NARRATE ──────────────────────────────────────────────────
        combined_gaps = list({g.description: g for g in all_gaps + investigation_plan.gaps}.values())
        narration = await narrate(
            context, verified,
            previous_narrative=narrative,
            gaps=combined_gaps,
            kill_chain=kill_chain,
            cycle=cycle_num,
            llm_client=llm_client,
            compressed_prior=compressed_prior,
        )
        narrative = narration.get("narrative", narrative)
        # Keep all_gaps as Gap objects (don't overwrite with serialized dicts)
        all_gaps = combined_gaps

        # ── PERSIST CYCLE TO SESSION STORE ──────────────────────────────────
        cycle_summary_for_store = {
            "cycle": cycle_num,
            "hypothesis": investigation_plan.hypothesis if investigation_plan else "",
            "findings_verified": len(verified),
            "findings_rejected": len(rejected),
            "findings_weak": len(weak),
        }
        resumable_state = {
            "narrative": narrative,
            "all_verified": all_verified,
            "all_gaps": all_gaps,
            "corrective_feedback": corrective_feedback,
            "cycle_count": cycle_num,
        }
        session.append_cycle(cycle_summary_for_store, resumable_state)

        # ── 5. BUILD CYCLE RECORD ────────────────────────────────────────
        cycle_result = AgentCycle(
            cycle=cycle_num,
            plan=investigation_plan,
            raw_findings=raw_findings,
            verified=verified,
            rejected=rejected,
            weak=weak,
            narrative_delta=narrative,
            tokens_used=0,  # TODO: wire actual token counting
            queries_used=len(raw_findings),
        )
        all_cycles.append(cycle_result)
        total_queries += cycle_result.queries_used

        # ── 6. LOOP DECISION ────────────────────────────────────────────
        has_new_findings = len(verified) > 0
        fetchable_gaps = [g for g in investigation_plan.gaps if g.type == "auto_fetchable"]
        human_prompt_gaps = [g for g in investigation_plan.gaps if g.type == "connector_disabled"]
        unknown_gaps = [g for g in investigation_plan.gaps if g.type == "unknown_source"]
        cross_domain_gaps = [g for g in investigation_plan.gaps if g.type == "cross_domain"]

        if not has_new_findings and not fetchable_gaps:
            # Harness completion checklist — mechanical, not self-reported.
            verifier_ran = (len(verified) + len(rejected) + len(weak)) == len(raw_findings)
            narrator_produced_output = bool(narration.get("narrative", "").strip())
            has_cumulative_findings = len(all_verified) > 0

            if not verifier_ran:
                _retry_v = getattr(context, "_verifier_retry_count", 0)
                if _retry_v >= 2:
                    close_reason = "verifier_count_mismatch"
                    LOGGER.error(
                        "Harness: Verifier count mismatch exceeded retry limit — closing"
                    )
                    break
                context._verifier_retry_count = _retry_v + 1  # type: ignore[attr-defined]
                LOGGER.warning(
                    "Harness: Verifier output count (%d) != raw finding count (%d) — "
                    "continuing cycle to re-verify",
                    len(verified) + len(rejected) + len(weak), len(raw_findings),
                )
                continue

            if not narrator_produced_output:
                _retry_n = getattr(context, "_narrator_retry_count", 0)
                if _retry_n >= 2:
                    close_reason = "narrator_no_output"
                    LOGGER.error(
                        "Harness: Narrator produced no output after retry limit — closing"
                    )
                    break
                context._narrator_retry_count = _retry_n + 1  # type: ignore[attr-defined]
                LOGGER.warning(
                    "Harness: Narrator produced empty output on cycle %d — "
                    "continuing to force narration",
                    cycle_num,
                )
                continue

            if not has_cumulative_findings:
                close_reason = "no_verified_findings"
                LOGGER.info("Harness: 0 verified findings across all cycles — closing as inconclusive")
                break

            close_reason = "investigation_complete"
            LOGGER.info(
                "Harness: Completion checklist passed — %d verified findings, "
                "Verifier ran, Narrator produced output",
                len(all_verified),
            )
            break

        if scope.exceeded:
            close_reason = "budget_exhausted"
            LOGGER.warning("Scope budget exhausted — closing investigation")
            break
    # ── CLOSE SESSION STORE ─────────────────────────────────────────────────────
    session.close(close_reason, {"narrative": narrative, "cycle_count": len(all_cycles)})

    # ── PERSIST INVESTIGATION TO MEMORY LAYERS ───────────────────────────────
    # Write investigation outcome back to TemporalRAG (Layer 2) and flush the
    # Global IdentityGraph (Layer 3) so future assessments benefit from findings.
    # Fire-and-forget — never block the return on persistence failures.
    try:
        import asyncio as _asyncio
        _asyncio.create_task(_persist_investigation_to_memory(
            context=context,
            close_reason=close_reason,
            all_verified=all_verified,
            kill_chain=kill_chain,
            narrative=narrative,
        ))
    except Exception as _pm_exc:
        LOGGER.debug('persist_investigation_to_memory scheduling failed: %s', _pm_exc)

    # ── FINAL AUDIT ──────────────────────────────────────────────────────
    audit("investigation_close",
          investigation_id=context.investigation_id,
          assessment_id=context.assessment_id,
          cycles=len(all_cycles),
          close_reason=close_reason,
          findings_verified=len(all_verified),
          findings_rejected=len(corrective_feedback),
          proposed_actions=len(all_proposed),
          gaps=len(all_gaps))

    return {
        "investigation_id": context.investigation_id,
        "assessment_id": context.assessment_id,
        "tenant_id": context.tenant_id,
        "cycles": [
            {
                "cycle": c.cycle,
                "hypothesis": c.plan.hypothesis if c.plan else "",
                "findings_verified": len(c.verified),
                "findings_rejected": len(c.rejected),
                "findings_weak": len(c.weak),
                "gaps": c.plan.gaps if c.plan else [],
            }
            for c in all_cycles
        ],
        "final_narrative": narrative,
        "confidence": narration.get("confidence", 0.0),
        "compliance_controls": narration.get("compliance_controls", []),
        "proposed_actions": [
            {
                "action_id": a.action_id,
                "zone": int(a.zone),
                "action_type": a.action_type,
                "description": a.description,
                "confidence": a.confidence,
                "status": a.status,
                "approval_token": a.approval_token,
                "compliance_controls": a.compliance_controls,
                "recipient": a.recipient,
                "recipient_evidence": a.recipient_evidence,
                "deadline_hours": a.deadline_hours,
                "citation": a.citation,
            }
            for a in all_proposed
        ],
        "gaps": [{"description": g.description, "type": g.type, "source_type": g.source_type,
                   "confidence_cap": g.confidence_cap, "impact": g.impact}
                  for g in all_gaps] if all_gaps else [],
        "kill_chain": [
            {
                "phase": kc.phase,
                "timestamp": kc.timestamp,
                "actor": kc.actor,
                "action": kc.action,
                "evidence_row_ids": kc.evidence_row_ids,
                "mitre_techniques": kc.mitre_techniques,
                "enables_phase_id": kc.enables_phase_id,
                "phase_id": kc.phase_id,
            }
            for kc in kill_chain
        ],
        "close_reason": close_reason,
        "total_cycles": len(all_cycles),
        "total_findings_verified": len(all_verified),
        "total_tokens_used": total_tokens,
        "total_queries_used": total_queries,
        "scope_pct": scope.pct,
        "elapsed_seconds": time.time() - context.created_ts,
        "memory_artifacts": [
            {
                "artifact_type": a.artifact_type,
                "content": a.content,
                "confidence": a.confidence,
                "cycle": a.cycle,
                "actor": a.actor,
                "mitre_techniques": a.mitre_techniques,
            }
            for a in memory.artifacts
        ],
    }


async def _persist_investigation_to_memory(
    *,
    context: InvestigationContext,
    close_reason: str,
    all_verified: list,
    kill_chain: list,
    narrative: str,
) -> None:
    """Write investigation outcome to TemporalRAG (incident index) and flush the
    Global IdentityGraph.  Called as a fire-and-forget task after the main loop."""
    import asyncio

    # Only index completed or no-more-leads investigations — skip budget/error cases
    if close_reason not in ('investigation_complete', 'no_more_leads', 'no_verified_findings'):
        return

    def _sync_persist() -> None:
        try:
            from src.core.ingest.assessment_worker import _get_incident_index, _get_trace_store
            from src.analysis.temporal_rag_dispatch import (
                TemporalRAGProvider, _signature_from_narrative,
            )
            from datetime import datetime, timezone

            incident_index = _get_incident_index()

            # Build a lightweight narrative dict from verified findings
            techniques: list = []
            phases: list = []
            for f in all_verified:
                for t in (getattr(f, 'mitre_techniques', None) or []):
                    if t and t not in techniques:
                        techniques.append(t)
                phase = getattr(f, 'kill_chain_phase', None) or ''
                if phase and phase not in phases:
                    phases.append(phase)

            synthetic_narrative = {
                'verdict': 'VALIDATED_BREACH' if all_verified else 'REQUIRES_INVESTIGATION',
                'mitre_techniques': techniques,
                'kill_chain_stage': phases[0] if phases else 'unknown',
                'affected_data': {},
                'affected_principals': {},
            }
            sig = _signature_from_narrative(synthetic_narrative)
            now = datetime.now(timezone.utc).isoformat()

            incident_index.index_incident(
                tenant_id=context.tenant_id,
                cluster_id=context.cluster_id or context.assessment_id,
                signature=sig,
                valid_time_start=now,
                valid_time_end=now,
                transaction_time=now,
                narrative_summary=narrative[:500] if narrative else '',
                outcome_summary=(
                    f"close_reason:{close_reason},findings:{len(all_verified)}"
                ),
            )
            LOGGER.info(
                'TemporalRAG indexed investigation result for %s (%d findings)',
                context.assessment_id, len(all_verified),
            )
        except Exception as exc:
            LOGGER.debug('persist investigation to TemporalRAG failed: %s', exc)

        try:
            from src.core.graph.global_identity_graph import flush_global_identity_graph
            flush_global_identity_graph()
        except Exception as exc:
            LOGGER.debug('global_identity_graph flush failed: %s', exc)

    try:
        await asyncio.to_thread(_sync_persist)
    except Exception as exc:
        LOGGER.debug('_persist_investigation_to_memory failed: %s', exc)


# ── Resume helpers ─────────────────────────────────────────────────────────────

def _rebuild_verified_findings(raw_list: List[Dict]) -> List[Any]:
    """Reconstruct VerifiedFinding objects from serialised dicts (best-effort)."""
    from src.agents.types import RawFinding, VerifiedFinding, RejectionReason
    out = []
    for item in raw_list:
        raw_data = item.get("raw", {})
        raw = RawFinding(
            step_index=raw_data.get("step_index", 0),
            tool=raw_data.get("tool", ""),
            summary=raw_data.get("summary", ""),
            evidence=raw_data.get("evidence", {}),
            source_count=raw_data.get("source_count", 1),
            data_volume_bytes=raw_data.get("data_volume_bytes", 0),
        )
        rej_data = item.get("rejection_reason") or {}
        vf = VerifiedFinding(
            raw=raw,
            confidence=item.get("confidence", 0.0),
            dread_score=item.get("dread_score", 0.0),
            compliance_controls=item.get("compliance_controls", []),
            rejection_reason=RejectionReason(**rej_data) if rej_data else None,
            weak=item.get("weak", False),
            reverification=item.get("reverification", {}),
        )
        out.append(vf)
    return out


def _rebuild_gaps(raw_list: List[Dict]) -> List[Any]:
    from src.agents.types import Gap
    return [
        Gap(
            description=g.get("description", ""),
            type=g.get("type", "unknown_source"),
            source_type=g.get("source_type", ""),
            confidence_cap=float(g.get("confidence_cap", 1.0)),
            suggested_fields=g.get("suggested_fields", []),
            impact=g.get("impact", ""),
        )
        for g in raw_list
        if isinstance(g, dict)
    ]


def _rebuild_rejection_reasons(raw_list: List[Dict]) -> List[Any]:
    from src.agents.types import RejectionReason
    return [
        RejectionReason(
            type=r.get("type", ""),
            actor=r.get("actor", ""),
            ip=r.get("ip", ""),
            phase=r.get("phase", ""),
            detail=r.get("detail", ""),
        )
        for r in raw_list
        if isinstance(r, dict)
    ]


async def resume_investigation(
    session_id: str,
    assessment_summary: Dict[str, Any],
    *,
    engagement_actors: Optional[Set[str]] = None,
    engagement_ips: Optional[Set[str]] = None,
    llm_client: Any = None,
) -> Dict[str, Any]:
    """Resume an interrupted investigation from its last persisted cycle.

    Loads the session state from the store, reconstructs the agent loop state,
    and continues from where it left off. Returns the same shape as run_investigation().
    """
    record = InvestigationSessionStore.load(session_id)
    if not record:
        return {"error": f"session {session_id!r} not found", "session_id": session_id}

    if record["status"] == "complete":
        return {
            "error": "investigation already complete",
            "session_id": session_id,
            "close_reason": record.get("close_reason", ""),
        }

    state = record.get("state") or {}
    completed_cycles = record.get("cycles_completed", 0)

    LOGGER.info(
        "Resuming investigation %s — %d cycles completed, picking up at cycle %d",
        session_id, completed_cycles, completed_cycles + 1,
    )

    context = InvestigationContext(
        assessment_id=record["assessment_id"],
        tenant_id=record["tenant_id"],
        investigation_id=session_id,
    )
    # Reduce the budget by what was already consumed; run at least 1 more cycle
    remaining_budget = max(context.max_cycles - completed_cycles, 1)
    context.max_cycles = remaining_budget

    return await run_investigation(
        context,
        assessment_summary,
        engagement_actors=engagement_actors,
        engagement_ips=engagement_ips,
        llm_client=llm_client,
        cluster_id=record.get("cluster_id", ""),
        _resume_state=state,
    )
