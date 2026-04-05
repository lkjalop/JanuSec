"""Persona formatting helpers for LLM summaries.

Provides simple templates for different analyst personas and a helper
to render a prompt fragment for the LLM based on persona and row context.
"""
from typing import Dict

TEMPLATES: Dict[str, str] = {
    'analyst': (
        "You are a security analyst. Produce a concise, actionable summary for the following artifact. "
        "Focus on what happened, likely impact, recommended mitigations, and confidence. Keep to 4-6 sentences.\n\n"),
    'manager': (
        "You are a security manager. Summarize the incident with business impact, prioritization, and recommended next steps. "
        "Keep language high-level and include an estimated severity label.\n\n"),
    'forensics': (
        "You are a forensic investigator. Provide a step-by-step investigation checklist, observed indicators, timelines, and artifacts to collect. "
        "Be precise and technical.\n\n"),
}


def render_persona_prompt(persona: str, context: Dict) -> str:
    persona_key = persona if persona in TEMPLATES else 'analyst'
    tpl = TEMPLATES.get(persona_key, TEMPLATES['analyst'])
    # Very small context injection; LLM prompt assembly should be done elsewhere
    brief = ''
    if context:
        parts = []
        if 'verdict' in context: parts.append(f"Verdict: {context.get('verdict')}")
        if 'triage_score' in context: parts.append(f"Triage: {context.get('triage_score')}")
        if 'factors' in context and isinstance(context.get('factors'), list):
            parts.append('Signals: ' + ', '.join(context.get('factors')[:6]))
        brief = '\n'.join(parts) + '\n\n' if parts else ''
    return tpl + brief
