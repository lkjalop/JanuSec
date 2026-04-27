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
    InvestigationContext,
    InvestigationPlan,
    VerifiedFinding,
)

LOGGER = logging.getLogger(__name__)

_NARRATOR_SYSTEM = """\
You are a security investigation narrator writing for a CEO audience.
Given verified findings from an investigation cycle, update the narrative.

RULES:
1. Write in plain business English. No jargon without explanation.
2. Lead with WHAT HAPPENED, then HOW, then IMPACT.
3. Mention specific evidence (IPs, usernames, timestamps) concisely.
4. Note any data gaps that limit confidence.
5. End with a single-sentence risk summary.
6. Maximum 200 words.
7. Do NOT invent findings. Only report what is in the verified evidence.
"""


def build_narrator_prompt(
    context: InvestigationContext,
    verified: List[VerifiedFinding],
    previous_narrative: str = "",
    gaps: List[str] | None = None,
    cycle: int = 1,
) -> str:
    """Build the Narrator's LLM prompt."""
    sections = [_NARRATOR_SYSTEM, ""]

    if previous_narrative:
        sections.append("## Previous Narrative (update, don't repeat)")
        sections.append(previous_narrative[:1000])
        sections.append("")

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
            sections.append(f"- {g}")
        sections.append("")

    sections.append("Write the updated narrative now (max 200 words).")
    return "\n".join(sections)


def compute_aggregate_confidence(
    verified: List[VerifiedFinding],
    gaps: List[str] | None = None,
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
    gaps: List[str] | None = None,
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
        "gaps": gaps or [],
        "findings_count": len(verified),
    }
