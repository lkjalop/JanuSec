"""
Narrator agent — composes the living narrative from verified findings.

The Narrator:
  1. Merges new verified findings into the existing narrative
  2. Updates compliance chip set
  3. Appends to the evidence chain timeline
  4. Adjusts the overall confidence score (algorithmic, not LLM)
  5. Surfaces gaps as "INVESTIGATION INCOMPLETE" callouts
  6. Produces the CEO-readable prose
"""
from __future__ import annotations

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
2. Cite specific timestamps, actors, and IPs.
3. Include row references in [brackets] when available.
4. Do NOT use bullet points or numbered lists.
5. Note any data gaps that limit confidence.
6. End with one-sentence risk summary.
7. Maximum 200 words.
8. Do NOT invent findings. Only report what is in the verified evidence.
9. Use plain business English. No jargon without explanation.
"""


def build_narrator_prompt(
    context: InvestigationContext,
    verified: List[VerifiedFinding],
    previous_narrative: str = "",
    gaps: List[Gap] | None = None,
    kill_chain: list | None = None,
    cycle: int = 1,
) -> str:
    """Build the Narrator's LLM prompt."""
    sections = [_NARRATOR_SYSTEM, ""]

    if previous_narrative:
        sections.append("## Previous Narrative (update, don't repeat)")
        sections.append(previous_narrative[:1000])
        sections.append("")

    # Kill chain timeline (Fix 4: causal order instead of bullets)
    if kill_chain:
        sections.append(f"## Kill Chain (causal order, Cycle {cycle})")
        for p in kill_chain:
            ts_str = p.timestamp.strftime("%Y-%m-%d %H:%M") if hasattr(p, 'timestamp') else "unknown"
            rows_str = str(p.evidence_row_ids[:3]) if p.evidence_row_ids else "[]"
            mitre_str = ", ".join(p.mitre_techniques[:3]) if p.mitre_techniques else "N/A"
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

    return max(round(base - gap_penalty, 3), 0.0)


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
