from typing import Dict, Any, List, Optional


BASE_TEMPERATURE = 0.3


PERSONA_TEMPLATES: Dict[str, Dict[str, Any]] = {
    'executive': {
        'tone': 'concise, non-technical, decision-focused',
        'instructions': 'Summarize the incident, business risk, and recommended executive action in 3 bullets. Translate severity into operational/financial/legal impact. Use simple language with no jargon.'
    },
    'soc_analyst': {
        'tone': 'technical, evidence-first, actionable',
        'instructions': 'List key indicators, suggested triage steps, and one-line justification for each. Include what changed, what is exploitable now, and what needs immediate ticketing.'
    },
    'compliance': {
        'tone': 'formal, controls-oriented',
        'instructions': 'Identify impacted controls, disclosure requirements, remediation timeline, and regulatory obligations (GDPR/SOC2/PCI). Link each finding to a framework control.'
    },
    'threat_hunter': {
        'tone': 'analytical, hypothesis-driven, statistical',
        'instructions': 'Describe the hunting hypothesis, supporting evidence, Bayesian confidence, MITRE ATT&CK techniques, and suggested pivot queries. Include factor weights and anomaly signals.'
    },
    'mssp': {
        'tone': 'client-facing, SLA-aware, concise',
        'instructions': 'Summarize severity, affected tenant, SLA status, and next escalation step. Flag any SLA breach risk. Keep to 5 lines max per finding.'
    },
    'forensics': {
        'tone': 'precise, evidence-chain-focused, chain-of-custody aware',
        'instructions': 'List artifacts to collect in order, execution ancestry to validate, persistence mechanisms to check, and network pivots. Specify preservation steps before containment. Include hash values and timestamps where available.'
    },
}

# Template metadata helps track changes and authoring
PERSONA_TEMPLATES_META = {
    'version': '0.1.0',
    'author': 'devteam',
    'last_updated': '2025-12-18'
}


def build_incident_prompt(persona: str, incident: Dict[str, Any], examples: Optional[List[Dict[str, Any]]] = None, temperature: Optional[float] = None) -> Dict[str, Any]:
    """Return a structured prompt object for LLM clients.

    The returned dict contains `messages` (chat-style) and meta like `temperature`.
    """
    persona = persona if persona in PERSONA_TEMPLATES else 'soc_analyst'
    tpl = PERSONA_TEMPLATES[persona]
    temp = temperature if temperature is not None else BASE_TEMPERATURE
    header = f"You are a {persona} assistant. Tone: {tpl['tone']}. {tpl['instructions']}"
    # Build a short few-shot example set when provided
    messages: List[Dict[str, str]] = []
    messages.append({'role': 'system', 'content': header})
    if examples:
        for ex in examples:
            messages.append({'role': 'user', 'content': ex.get('input')})
            messages.append({'role': 'assistant', 'content': ex.get('output')})
    # Add the incident as user content
    messages.append({'role': 'user', 'content': f"Incident JSON:\n{incident}"})
    return {'messages': messages, 'temperature': temp, 'persona': persona}


def build_persona_prompt(persona: str, context: Dict[str, Any], base_summary: str = '', examples: Optional[List[Dict[str, Any]]] = None, temperature: Optional[float] = None) -> Dict[str, Any]:
    """Build a persona prompt suitable for cached_generate. Mirrors deep_analyze persona shape.

    Returns the same structure as `build_incident_prompt` (messages + meta).
    """
    tpl = PERSONA_TEMPLATES.get(persona) or PERSONA_TEMPLATES.get('soc_analyst')
    temp = temperature if temperature is not None else BASE_TEMPERATURE
    header = f"Persona: {persona}. Tone: {tpl.get('tone')}. {tpl.get('instructions')}"
    messages = [{'role': 'system', 'content': header}]
    if examples:
        for ex in examples:
            messages.append({'role': 'user', 'content': ex.get('input')})
            messages.append({'role': 'assistant', 'content': ex.get('output')})
    # attach context and base summary as a user message
    messages.append({'role': 'user', 'content': f"Context JSON:\n{context}"})
    # Explicitly list log gap checklist by severity when available
    try:
        logs = (context.get('dependency_status') or {}).get('logs') or {}
        gaps = logs.get('gaps') or []
        sources = logs.get('sources') or []
        if gaps or sources:
            lines: List[str] = []
            if gaps:
                lines.append('Log Gap Checklist:')
                for g in gaps[:20]:
                    sev = str(g.get('severity') or 'critical').upper()
                    name = g.get('name') or 'unknown'
                    msg = g.get('message') or ''
                    secs = int(g.get('seconds_since_ok') or 0)
                    ttl = int(g.get('ttl') or 0)
                    lines.append(f"- [{sev}] {name}: {msg} (stale {secs}s, ttl {ttl}s)")
            if sources:
                lines.append('Log Source Freshness:')
                for s in sources[:30]:
                    name = s.get('name')
                    sev = str(s.get('severity') or 'info').upper()
                    secs = int((s.get('seconds_since_ok') or 0) or 0)
                    ttl = int((s.get('ttl') or 0) or 0)
                    lines.append(f"- {name}: {sev} (age {secs}s, ttl {ttl}s)")
            if lines:
                messages.append({'role': 'user', 'content': '\n'.join(lines)})
    except Exception:
        pass
    messages.append({'role': 'user', 'content': f"Base Summary:\n{base_summary}"})
    return {'messages': messages, 'temperature': temp, 'persona': persona}


def parse_simple_bullets(llm_text: str) -> List[str]:
    """Heuristically parse bullet lines from an LLM text response."""
    lines = [l.strip() for l in llm_text.splitlines() if l.strip()]
    bullets = []
    for l in lines:
        if l.startswith('-') or l.startswith('*') or l.startswith('•'):
            bullets.append(l.lstrip('-*• ').strip())
        elif len(l) < 200 and l.endswith('.'):
            bullets.append(l)
    return bullets
import json
from typing import Any, Dict

SUMMARY_PROMPT_TEMPLATE = '''
You are a security analyst assistant. Produce a JSON object with keys: company_name (optional), recipients (array), key_findings (array of short strings), one_line_recommendation (string), and provenance (object).
Input Summary: {summary}
Top rows count: {row_count}
Return only the JSON object. Keep items concise.
'''


def build_summary_prompt_template(summary: Any, row_count: int) -> str:
    try:
        s = summary or {}
        return SUMMARY_PROMPT_TEMPLATE.format(summary=json.dumps(s), row_count=int(row_count or 0))
    except Exception:
        return SUMMARY_PROMPT_TEMPLATE.format(summary=str(summary), row_count=int(row_count or 0))


def parse_structured_summary_text(text: str) -> Dict[str, Any]:
    # Try to extract a JSON object from text
    try:
        j = json.loads(text)
        return j
    except Exception:
        try:
            start = text.find('{')
            end = text.rfind('}')
            if start != -1 and end != -1 and end > start:
                sub = text[start:end+1]
                return json.loads(sub)
        except Exception:
            pass
    return {'text': text}
