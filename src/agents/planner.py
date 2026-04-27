"""
Planner agent — decides what to investigate next.

Receives:
  • assessment summary (ingested source types, row counts, time range)
  • current HopGraph state (known entities, edge types)
  • previous cycle results (verified findings, rejected findings)
  • CorrectiveRAG history (known false-positive patterns to avoid)
  • data gap inventory (what's missing)

Outputs:
  • InvestigationPlan with structured steps + identified gaps
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from src.agents.types import (
    ActionZone,
    InvestigationContext,
    InvestigationPlan,
    PlanStep,
    VerifiedFinding,
)

LOGGER = logging.getLogger(__name__)

# LLM prompt template for the Planner
_PLANNER_SYSTEM = """\
You are a security investigation planner. Given the assessment context and
previous findings, produce a JSON investigation plan.

You MUST output valid JSON matching this schema:
{
  "hypothesis": "<one-sentence hypothesis about what happened>",
  "steps": [
    {
      "tool": "<tool name from AVAILABLE_TOOLS>",
      "params": { ... },
      "reason": "<why this step is needed>"
    }
  ],
  "gaps": ["<data source or information that is missing>"]
}

AVAILABLE_TOOLS: temporal_rag, hopgraph_query, nlp_search, duckdb_query,
                 dread_score, fetch_source, compliance_tag, action_propose

RULES:
1. Maximum 5 steps per plan.
2. Each step must have a clear reason.
3. Prefer multi-source cross-correlation.
4. Flag gaps — what data is missing that would increase confidence.
5. DO NOT propose Zone 2/3 actions (block/disable/notify) unless previous
   cycle found verified high-confidence findings.
6. If corrective feedback says a pattern is FP, do NOT re-investigate it.
"""


def build_planner_prompt(
    context: InvestigationContext,
    assessment_summary: Dict[str, Any],
    previous_findings: List[VerifiedFinding] | None = None,
    corrective_feedback: List[str] | None = None,
    gaps: List[str] | None = None,
    cycle: int = 1,
) -> str:
    """Build the full prompt for the Planner LLM call."""
    sections = [_PLANNER_SYSTEM, ""]

    # Assessment context
    sections.append("## Assessment Context")
    sections.append(f"Assessment ID: {context.assessment_id}")
    sections.append(f"Tenant: {context.tenant_id}")
    sections.append(f"Cycle: {cycle}/{context.max_cycles}")
    if context.initial_hypothesis:
        sections.append(f"Initial hypothesis: {context.initial_hypothesis}")
    sections.append(f"Summary: {json.dumps(assessment_summary, default=str)[:2000]}")
    sections.append("")

    # Previous findings
    if previous_findings:
        sections.append("## Previous Verified Findings")
        for vf in previous_findings[:10]:
            sections.append(f"- [{vf.confidence:.2f}] {vf.raw.summary[:200]}")
        sections.append("")

    # Corrective feedback
    if corrective_feedback:
        sections.append("## Known False Positives (DO NOT re-investigate)")
        for fb in corrective_feedback[:10]:
            sections.append(f"- {fb[:200]}")
        sections.append("")

    # Gaps
    if gaps:
        sections.append("## Known Data Gaps")
        for g in gaps[:10]:
            sections.append(f"- {g}")
        sections.append("")

    sections.append("Produce the investigation plan JSON now.")
    return "\n".join(sections)


def parse_plan_response(raw_text: str, cycle: int) -> InvestigationPlan:
    """Parse the LLM's JSON response into an InvestigationPlan.

    Robust: handles markdown code fences, partial JSON, etc.
    """
    # Strip markdown fences
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)

    # Attempt to find JSON object
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        text = text[start:end]

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        LOGGER.warning("Planner output is not valid JSON, creating minimal plan")
        return InvestigationPlan(
            cycle=cycle,
            hypothesis="Unable to parse planner output",
            steps=[],
            gaps=["Planner produced non-JSON output"],
        )

    hypothesis = data.get("hypothesis", "")
    steps = []
    for s in data.get("steps", [])[:5]:  # enforce max 5
        steps.append(PlanStep(
            tool=s.get("tool", ""),
            params=s.get("params", {}),
            reason=s.get("reason", ""),
        ))

    gaps = data.get("gaps", [])
    if isinstance(gaps, str):
        gaps = [gaps]

    return InvestigationPlan(
        cycle=cycle,
        hypothesis=hypothesis,
        steps=steps,
        gaps=gaps[:10],
    )


async def plan(
    context: InvestigationContext,
    assessment_summary: Dict[str, Any],
    *,
    previous_findings: List[VerifiedFinding] | None = None,
    corrective_feedback: List[str] | None = None,
    gaps: List[str] | None = None,
    cycle: int = 1,
    llm_client: Any = None,
) -> InvestigationPlan:
    """Run the Planner agent: build prompt → call LLM → parse plan.

    If no llm_client is provided, uses the default client.
    """
    prompt = build_planner_prompt(
        context, assessment_summary,
        previous_findings=previous_findings,
        corrective_feedback=corrective_feedback,
        gaps=gaps,
        cycle=cycle,
    )

    if llm_client is None:
        from src.integrations.llm_client import DEFAULT_CLIENT
        llm_client = DEFAULT_CLIENT

    try:
        resp = llm_client.generate(
            prompt,
            max_tokens=1024,
            tenant_id=context.tenant_id,
            model=os.environ.get("OLLAMA_MODEL"),
        )
        raw_text = resp.get("text", "")
    except Exception as exc:
        LOGGER.exception("Planner LLM call failed")
        raw_text = json.dumps({
            "hypothesis": f"LLM error: {exc}",
            "steps": [],
            "gaps": ["LLM unavailable"],
        })

    return parse_plan_response(raw_text, cycle)
