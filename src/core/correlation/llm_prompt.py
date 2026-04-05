from __future__ import annotations
from typing import Dict, Any


def build_tier1_prompt(summary: Dict[str, Any], event: Dict[str, Any]) -> str:
    """Return a deterministic LLM prompt for Tier-1 triage.

    The prompt is intentionally concise and enumerates: title, score, MITRE, reasons,
    top factors, and raw evidence snippet. It asks for a single-line recommended action,
    a short rationale (1-2 sentences), and suggested next steps (2 bullets).
    """
    lines = []
    lines.append("TIER-1 TRIAGE SUMMARY")
    lines.append(f"Title: {summary.get('title')}")
    lines.append(f"Score: {summary.get('score'):.3f}")
    mitre = ', '.join(summary.get('mitre', []))
    lines.append(f"MITRE: {mitre}")
    lines.append("Reasons:")
    for r in summary.get('reason', [])[:6]:
        lines.append(f" - {r}")
    lines.append("Top Factors:")
    for f in summary.get('top_factors', [])[:5]:
        lines.append(f" - {f.get('name')} (score={f.get('score'):.2f})")
    lines.append("Evidence Snippet:")
    evidence = summary.get('reason') or []
    lines.append(' | '.join(evidence[:3]))
    lines.append("")
    lines.append("Task:")
    lines.append("1) Provide a one-line recommended action (ACCEPT/ESCALATE/NO_ACTION).")
    lines.append("2) Give a 1-2 sentence rationale.")
    lines.append("3) Recommend up to 2 next investigation steps (bullet list).")
    lines.append("")
    lines.append("Respond with a JSON object only with fields: action, rationale, next_steps (array of strings).")
    return "\n".join(lines)
