from __future__ import annotations
from typing import Dict, Any, List

SUSPECT_PROMPT_TOKENS = (
    "ignore previous", "system prompt", "do anything", "jailbreak", "override policy",
    "bypass", "disable safety", "as an expert", "simulation only"
)


def detect_ai_signals(event: Dict[str, Any]) -> List[str]:
    """Lightweight AI security heuristics (MVP).

    Returns a list of factor names to consider emitting. This module is not
    auto-wired; callers can import and use explicitly behind flags.
    """
    out: List[str] = []
    d = event or {}
    domain = str(d.get('domain') or d.get('source_type') or '').lower()
    if domain != 'ai':
        return out

    prompt = (d.get('prompt') or '').lower()
    tool = (d.get('tool') or d.get('tool_name') or '')
    tool_args = d.get('tool_args') or {}
    guardrail = (d.get('guardrail') or '')
    output_text = (d.get('output') or d.get('model_output') or '')

    # Prompt injection / jailbreak token matches
    if prompt and any(tok in prompt for tok in SUSPECT_PROMPT_TOKENS):
        out.append('prompt_injection')

    # Tool abuse: tool present but missing policy context or suspicious args
    if tool:
        policy_id = d.get('policy_id') or d.get('policy')
        if not policy_id:
            out.append('tool_abuse')
        else:
            try:
                if isinstance(tool_args, dict):
                    joined = ' '.join([str(v) for v in tool_args.values()])
                else:
                    joined = str(tool_args)
                if any(k in joined.lower() for k in ('rm -rf', 'drop table', 'secrets', 'token=')):
                    out.append('tool_abuse')
            except Exception:
                pass

    # Sensitive output leak: very light heuristic; real logic should reuse secrets/redaction
    if isinstance(output_text, str) and any(sig in output_text for sig in ('AKIA', 'BEGIN PRIVATE KEY', 'password=')):
        out.append('sensitive_output_leak')

    # Guardrail hard-blocks imply attempted abuse
    if guardrail and str(guardrail).lower() in ('blocked', 'deny', 'rejected'):
        if 'prompt_injection' not in out:
            out.append('prompt_injection')

    return out

__all__ = ['detect_ai_signals']

