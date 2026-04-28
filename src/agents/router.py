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
    ProposedAction,
    RejectionReason,
    VerifiedFinding,
)
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

    for cycle_num in range(1, context.max_cycles + 1):
        LOGGER.info("=== Investigation %s — Cycle %d/%d ===",
                     context.investigation_id, cycle_num, context.max_cycles)

        # ── 1. PLAN ──────────────────────────────────────────────────────
        investigation_plan = await plan(
            context,
            assessment_summary,
            previous_findings=all_verified[-20:] if all_verified else None,
            corrective_feedback=corrective_feedback[-20:] if corrective_feedback else None,
            gaps=all_gaps[-10:] if all_gaps else None,
            cycle=cycle_num,
            llm_client=llm_client,
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
        )
        narrative = narration.get("narrative", narrative)
        # Keep all_gaps as Gap objects (don't overwrite with serialized dicts)
        all_gaps = combined_gaps

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
            close_reason = "investigation_complete"
            LOGGER.info("No new findings and no fetchable gaps — investigation complete")
            break

        if scope.exceeded:
            close_reason = "budget_exhausted"
            LOGGER.warning("Scope budget exhausted — closing investigation")
            break

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
        "confidence": narration.get("confidence", 0.0) if 'narration' in dir() else 0.0,
        "compliance_controls": narration.get("compliance_controls", []) if 'narration' in dir() else [],
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
            for kc in (kill_chain if 'kill_chain' in dir() else [])
        ],
        "close_reason": close_reason,
        "total_cycles": len(all_cycles),
        "total_findings_verified": len(all_verified),
        "total_tokens_used": total_tokens,
        "total_queries_used": total_queries,
        "scope_pct": scope.pct,
        "elapsed_seconds": time.time() - context.created_ts,
    }
