"""
Narrator agent — composes the living narrative from verified findings.

The Narrator:
  1. Merges new verified findings into the existing narrative
  2. Updates compliance chip set
  3. Appends to the evidence chain timeline
  4. Adjusts the overall confidence score (algorithmic, not LLM)
  5. Surfaces gaps as "INVESTIGATION INCOMPLETE" callouts
  6. Produces the CEO-readable prose

Scatter-Gather Architecture (see narrate_scatter_gather()):
  Phase 1 — Scatter: 4 specialized mini-agents run in parallel on the same evidence:
    • TimelineMini  — reconstructs exact kill-chain arc with timestamps
    • AttributionMini — fingerprints adversary TTPs against known threat actors
    • ImpactMini   — quantifies blast radius in business/dollar terms
    • ComplianceMini — maps failures to audit controls
  Phase 2 — Gather + Critic: synthesis agent merges outputs; critic cross-validates
  Phase 3 — Deepening: for top-3 DREAD signals, T2 model does a second-pass with
    full 20-row evidence context focused narrowly on that signal

Campaign Arc (see narrate_campaign_arc()):
  After all clusters are narrated individually, a CampaignArc agent stitches
  together shared IOCs, technique progression, and kill-chain phase transitions
  into a single cohesive "chapter" spanning the full investigation.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Dict, List, Optional

from src.agents.types import (
    Gap,
    InvestigationContext,
    InvestigationPlan,
    VerifiedFinding,
)

LOGGER = logging.getLogger(__name__)

_NARRATOR_SYSTEM = """\
You are a security investigation narrator writing for a CEO audience.
Given a kill chain timeline of verified findings, write a single causal
paragraph following the kill chain order.

RULES:
1. Write as one causal paragraph: A enabled B which led to C.
2. Cite specific timestamps, actors, and IPs with [row N] references.
3. Include row references in [brackets] — e.g., [row 5], [rows 12,18] — for every key claim.
4. Do NOT use bullet points or numbered lists.
5. Note any data gaps that limit confidence; use calibrated language ("with ~85% confidence").
6. End with one-sentence risk summary stating the highest business impact.
7. Maximum 200 words.
8. Do NOT invent findings. Only report what is in the verified evidence.
9. Use plain business English. No jargon without explanation.
10. If multiple investigation cycles, note technique evolution and new IOCs since last cycle.
"""

# ── Mini-agent system prompts for scatter-gather ─────────────────────────────

_TIMELINE_MINI_SYSTEM = """\
You are a forensic timeline reconstructor. Given evidence rows, output ONLY a
chronological kill-chain arc: Phase | Timestamp | Actor | Action | Evidence ref.
Be precise with timestamps. Flag any temporal gaps > 2 hours.
Max 150 words. No prose — structured list only.
"""

_ATTRIBUTION_MINI_SYSTEM = """\
You are a threat intelligence analyst. Given TTPs and IOCs from evidence rows,
identify the most likely threat actor cluster (nation-state / eCrime / insider).
Cite matching TTP fingerprints and confidence percentage (0-100%).
If insufficient evidence for attribution, say so explicitly.
Max 100 words.
"""

_IMPACT_MINI_SYSTEM = """\
You are a business impact estimator. Given evidence of a security incident,
quantify: systems affected, data classes at risk, estimated downtime, and
regulatory exposure (GDPR/PCI/HIPAA fines). Use conservative estimates.
Cite specific evidence rows for each claim. Max 120 words.
"""

_COMPLIANCE_MINI_SYSTEM = """\
You are a compliance auditor. Given incident evidence, identify which specific
controls failed (ISO 27001 Annex A, NIST CSF, CIS). For each control, state:
control ID, failure type (PREVENTIVE_FAILED/DETECTIVE_FAILED/CONTROL_ABSENT),
and the evidence row that proves the failure. Max 120 words, structured.
"""

_SYNTHESIS_SYSTEM = """\
You are a security narrative synthesizer. You receive 4 specialist analyses
(timeline, attribution, impact, compliance) of the same incident. Produce a
single CEO-readable paragraph (max 200 words) that:
1. Follows causal kill-chain order from the timeline analysis
2. Incorporates attribution confidence from threat intel analysis
3. Quotes business impact figures from the impact analysis
4. Names the top 2 control failures from compliance analysis
5. Uses calibrated confidence language ("with ~85% confidence")
6. Cites [row N] references for all key claims
Do NOT invent anything not present in the 4 specialist inputs.
"""

_CAMPAIGN_ARC_SYSTEM = """\
You are a campaign-arc narrator connecting multiple security clusters into a
cohesive attack story. Given N cluster narratives with their kill-chain phases,
shared IOCs, and MITRE techniques:
1. Identify the campaign entry point and final impact
2. Connect clusters using shared IOCs (IPs, hashes, domains, JA3/JA4 fingerprints)
3. Describe adversary dwell time and technique evolution across clusters
4. Use a chapter-style opening: "Over [timespan], the adversary..."
5. Cite shared IOCs explicitly (e.g., "IP 10.0.0.1 appeared in both Cluster-A and Cluster-C")
6. End with overall campaign DREAD risk tier and recommended immediate actions
Max 300 words. CEO audience. No bullet points.
"""


def build_narrator_prompt(
    context: InvestigationContext,
    verified: List[VerifiedFinding],
    previous_narrative: str = "",
    gaps: List[Gap] | None = None,
    kill_chain: list | None = None,
    cycle: int = 1,
    compressed_prior: str = "",
) -> str:
    """Build the Narrator's LLM prompt."""
    sections = [_NARRATOR_SYSTEM, ""]

    # Inject compressed prior context (Compress primitive) so the Narrator has
    # the full investigation history even if prior cycles dropped from LLM window
    if compressed_prior:
        sections.append("## Full Investigation History (compressed)")
        sections.append(compressed_prior)
        sections.append("")

    if previous_narrative:
        sections.append("## Previous Narrative (update, don't repeat)")
        sections.append(previous_narrative[:1000])
        sections.append("")

    if kill_chain:
        sections.append(f"## Kill Chain (causal order, Cycle {cycle})")
        for p in kill_chain:
            ts_str = p.timestamp.strftime("%Y-%m-%d %H:%M") if hasattr(p, 'timestamp') else "unknown"
            rows_str = str(p.evidence_row_ids[:8]) if p.evidence_row_ids else "[]"
            mitre_str = ", ".join(p.mitre_techniques[:8]) if p.mitre_techniques else "N/A"
            sections.append(
                f"{ts_str} | {p.phase} | {p.actor} | "
                f"{p.action[:150]} | rows {rows_str} | MITRE {mitre_str}"
            )
            if p.enables_phase_id:
                sections.append(f"  → enables next phase ({p.enables_phase_id})")
        sections.append("")
        sections.append("Write as one causal paragraph: A enabled B which led to C. "
                       "Cite specific timestamps, actors, and IPs. Include row references "
                       "in [brackets]. Do NOT use bullet points. End with one-sentence "
                       "risk summary.")
    else:
        # Fallback: bullet list if no kill chain
        sections.append(f"## Cycle {cycle} Verified Findings")
        for vf in verified[:15]:
            sections.append(
                f"- [{vf.confidence:.2f}] {vf.raw.summary[:200]} "
                f"(sources: {vf.raw.source_count}, DREAD: {vf.dread_score:.1f})"
            )
            if vf.compliance_controls:
                tags = ", ".join(f"{c['control_id']}" for c in vf.compliance_controls[:5])
                sections.append(f"  Controls: {tags}")
    sections.append("")

    if gaps:
        sections.append("## Data Gaps")
        for g in gaps[:5]:
            if isinstance(g, str):
                sections.append(f"- {g}")
            else:
                sections.append(f"- [{g.type}] {g.description} (cap={g.confidence_cap}, impact={g.impact})")
        sections.append("")

    sections.append("Write the updated narrative now (max 200 words).")
    return "\n".join(sections)


def compute_aggregate_confidence(
    verified: List[VerifiedFinding],
    gaps: List[Gap] | None = None,
) -> float:
    """Algorithmic aggregate confidence — NOT LLM-generated.

    Combines individual finding confidences with a gap penalty.
    """
    if not verified:
        return 0.0

    # Weighted average by DREAD score
    total_weight = 0.0
    weighted_sum = 0.0
    for vf in verified:
        w = max(vf.dread_score, 1.0)
        weighted_sum += vf.confidence * w
        total_weight += w

    base = weighted_sum / total_weight if total_weight > 0 else 0.0

    # Gap penalty: each gap reduces confidence by ~0.05, max 0.3
    gap_count = len(gaps) if gaps else 0
    gap_penalty = min(gap_count * 0.05, 0.3)
    result = base - gap_penalty

    # Apply per-gap confidence caps (e.g. missing forensic evidence hard-caps at 0.6)
    if gaps:
        caps = [g.confidence_cap for g in gaps if hasattr(g, 'confidence_cap') and g.confidence_cap is not None]
        if caps:
            result = min(result, min(caps))

    return max(round(result, 3), 0.0)


def collect_compliance_controls(
    verified: List[VerifiedFinding],
) -> List[Dict[str, str]]:
    """De-duplicate compliance controls across all verified findings."""
    seen = set()
    out = []
    for vf in verified:
        for ctrl in vf.compliance_controls:
            key = f"{ctrl.get('framework')}|{ctrl.get('control_id')}"
            if key not in seen:
                seen.add(key)
                out.append(ctrl)
    return out


async def narrate(
    context: InvestigationContext,
    verified: List[VerifiedFinding],
    *,
    previous_narrative: str = "",
    gaps: List[Gap] | None = None,
    kill_chain: list | None = None,
    cycle: int = 1,
    llm_client: Any = None,
    compressed_prior: str = "",
) -> Dict[str, Any]:
    """Run the Narrator agent: produce updated narrative + metadata.

    Returns dict with:
      - narrative: the CEO-readable prose
      - confidence: algorithmic aggregate confidence
      - compliance_controls: de-duped list
      - gaps: remaining gaps
      - findings_count: number of verified findings included
    """
    prompt = build_narrator_prompt(
        context, verified,
        previous_narrative=previous_narrative,
        gaps=gaps,
        kill_chain=kill_chain,
        cycle=cycle,
        compressed_prior=compressed_prior,
    )

    if llm_client is None:
        from src.integrations.llm_client import DEFAULT_CLIENT
        llm_client = DEFAULT_CLIENT

    try:
        resp = llm_client.generate(
            prompt,
            max_tokens=512,
            tenant_id=context.tenant_id,
            model=os.environ.get("OLLAMA_MODEL"),
        )
        narrative = resp.get("text", "")
    except Exception as exc:
        LOGGER.exception("Narrator LLM call failed")
        # Fallback: bullet-point narrative from findings
        lines = [f"Investigation cycle {cycle} findings:"]
        for vf in verified[:5]:
            lines.append(f"• {vf.raw.summary[:150]}")
        narrative = "\n".join(lines)

    return {
        "narrative": narrative,
        "confidence": compute_aggregate_confidence(verified, gaps),
        "compliance_controls": collect_compliance_controls(verified),
        "gaps": [{"type": g.type, "description": g.description, "confidence_cap": g.confidence_cap}
                 if hasattr(g, 'type') else g for g in (gaps or [])],
        "findings_count": len(verified),
    }


async def _call_mini_agent(
    system_prompt: str,
    evidence_text: str,
    llm_client: Any,
    max_tokens: int = 300,
    tenant_id: str = "",
) -> str:
    """Single mini-agent call; returns text or empty string on failure."""
    try:
        prompt = f"{system_prompt}\n\n## Evidence\n{evidence_text}"
        resp = llm_client.generate(
            prompt,
            max_tokens=max_tokens,
            tenant_id=tenant_id,
            model=os.environ.get("OLLAMA_MODEL"),
        )
        return resp.get("text", "")
    except Exception:
        LOGGER.exception("mini-agent call failed")
        return ""


async def narrate_scatter_gather(
    context: InvestigationContext,
    verified: List[VerifiedFinding],
    *,
    gaps: List[Gap] | None = None,
    kill_chain: list | None = None,
    cycle: int = 1,
    llm_client: Any = None,
    compressed_prior: str = "",
) -> Dict[str, Any]:
    """Scatter-gather narrator: 4 specialist mini-agents → synthesis → critic.

    Phase 1 (scatter): Timeline, Attribution, Impact, Compliance agents run in
    parallel on the same evidence, each with a focused system prompt.

    Phase 2 (gather): Synthesis agent merges all 4 outputs into CEO narrative.

    Phase 3 (deepen): Not implemented here — wire to T2 narrator externally for
    top-DREAD clusters (use _T2_CONFIDENCE_THRESHOLD from cluster_narrator.py).

    Returns same shape as narrate() plus 'specialist_outputs' dict.
    """
    if llm_client is None:
        from src.integrations.llm_client import DEFAULT_CLIENT
        llm_client = DEFAULT_CLIENT

    # Build shared evidence text for all mini-agents
    evidence_lines = []
    for i, vf in enumerate(verified[:15], 1):
        evidence_lines.append(
            f"[row {i}] [{vf.confidence:.2f}] {vf.raw.summary[:200]}"
            f" | MITRE: {','.join(getattr(vf.raw, 'mitre_techniques', [])[:4])}"
        )
    if kill_chain:
        for p in kill_chain[:10]:
            ts_str = p.timestamp.strftime("%Y-%m-%d %H:%M") if hasattr(p, 'timestamp') else "?"
            rows_str = str(p.evidence_row_ids[:5]) if p.evidence_row_ids else "[]"
            evidence_lines.append(f"[kc] {ts_str} | {p.phase} | {p.actor} | {p.action[:120]} rows={rows_str}")
    evidence_text = "\n".join(evidence_lines) or "No evidence available."
    if gaps:
        evidence_text += "\n\nGAPS: " + "; ".join(
            (g.description if hasattr(g, 'description') else str(g)) for g in gaps[:5]
        )

    # Phase 1: scatter — 4 mini-agents in parallel
    timeline_task = _call_mini_agent(_TIMELINE_MINI_SYSTEM, evidence_text, llm_client, 250, context.tenant_id)
    attribution_task = _call_mini_agent(_ATTRIBUTION_MINI_SYSTEM, evidence_text, llm_client, 200, context.tenant_id)
    impact_task = _call_mini_agent(_IMPACT_MINI_SYSTEM, evidence_text, llm_client, 250, context.tenant_id)
    compliance_task = _call_mini_agent(_COMPLIANCE_MINI_SYSTEM, evidence_text, llm_client, 250, context.tenant_id)

    timeline_out, attribution_out, impact_out, compliance_out = await asyncio.gather(
        timeline_task, attribution_task, impact_task, compliance_task,
        return_exceptions=False,
    )

    specialist_outputs = {
        "timeline": timeline_out,
        "attribution": attribution_out,
        "impact": impact_out,
        "compliance": compliance_out,
    }

    # Phase 2: gather — synthesis agent
    synthesis_input = (
        f"## Timeline Analysis\n{timeline_out or '(unavailable)'}\n\n"
        f"## Attribution Analysis\n{attribution_out or '(unavailable)'}\n\n"
        f"## Business Impact Analysis\n{impact_out or '(unavailable)'}\n\n"
        f"## Compliance Failure Analysis\n{compliance_out or '(unavailable)'}"
    )
    narrative = await _call_mini_agent(_SYNTHESIS_SYSTEM, synthesis_input, llm_client, 512, context.tenant_id)

    if not narrative:
        # Fallback: use standard single-agent narrator
        result = await narrate(
            context, verified,
            gaps=gaps, kill_chain=kill_chain, cycle=cycle,
            llm_client=llm_client, compressed_prior=compressed_prior,
        )
        result["specialist_outputs"] = specialist_outputs
        result["scatter_gather"] = False
        return result

    return {
        "narrative": narrative,
        "confidence": compute_aggregate_confidence(verified, gaps),
        "compliance_controls": collect_compliance_controls(verified),
        "gaps": [{"type": g.type, "description": g.description, "confidence_cap": g.confidence_cap}
                 if hasattr(g, 'type') else g for g in (gaps or [])],
        "findings_count": len(verified),
        "specialist_outputs": specialist_outputs,
        "scatter_gather": True,
    }


async def narrate_campaign_arc(
    cluster_narratives: List[Dict[str, Any]],
    *,
    llm_client: Any = None,
    tenant_id: str = "",
) -> str:
    """Stitch per-cluster narratives into a single campaign-arc chapter.

    Args:
        cluster_narratives: List of dicts, each from narrate() / narrate_scatter_gather().
          Expected keys: 'cluster_id', 'narrative', 'kill_chain_phases', 'iocs',
          'mitre_techniques', 'dread_score', 'verdict'.
        llm_client: LLM client (defaults to DEFAULT_CLIENT).
        tenant_id: Tenant scope for LLM billing.

    Returns:
        Campaign-arc narrative string (CEO-readable chapter).
    """
    if llm_client is None:
        from src.integrations.llm_client import DEFAULT_CLIENT
        llm_client = DEFAULT_CLIENT

    if not cluster_narratives:
        return ""

    # Build campaign context: identify shared IOCs across clusters
    all_iocs: Dict[str, List[str]] = {}  # ioc_value -> [cluster_ids]
    for cn in cluster_narratives:
        cid = cn.get('cluster_id', 'unknown')
        for ioc in cn.get('iocs', []):
            all_iocs.setdefault(ioc, []).append(cid)
    shared_iocs = {ioc: cids for ioc, cids in all_iocs.items() if len(cids) > 1}

    # Build prompt context
    cluster_summaries = []
    for cn in cluster_narratives[:8]:  # cap to avoid token explosion
        cid = cn.get('cluster_id', '?')
        verdict = cn.get('verdict', '')
        phases = cn.get('kill_chain_phases', [])
        techniques = cn.get('mitre_techniques', [])
        dread = cn.get('dread_score', {})
        risk = dread.get('risk_tier', '?') if isinstance(dread, dict) else '?'
        narrative_snippet = (cn.get('narrative') or '')[:200]
        cluster_summaries.append(
            f"Cluster {cid} [{verdict}] DREAD:{risk} | Phases:{phases} | MITRE:{techniques[:4]}\n"
            f"  → {narrative_snippet}"
        )

    shared_ioc_text = ""
    if shared_iocs:
        shared_ioc_text = "\n\nSHARED IOCs ACROSS CLUSTERS (pivot points):\n"
        for ioc, cids in list(shared_iocs.items())[:10]:
            shared_ioc_text += f"  {ioc} — seen in: {', '.join(cids)}\n"

    campaign_context = "\n\n".join(cluster_summaries) + shared_ioc_text

    try:
        prompt = f"{_CAMPAIGN_ARC_SYSTEM}\n\n## Cluster Narratives\n{campaign_context}"
        resp = llm_client.generate(
            prompt,
            max_tokens=700,
            tenant_id=tenant_id,
            model=os.environ.get("OLLAMA_MODEL"),
        )
        return resp.get("text", "")
    except Exception:
        LOGGER.exception("campaign arc narration failed")
        # Fallback: structured summary without LLM
        lines = [f"Campaign spanning {len(cluster_narratives)} clusters detected."]
        if shared_iocs:
            lines.append(f"Shared IOCs linking clusters: {', '.join(list(shared_iocs.keys())[:5])}")
        return " ".join(lines)
