"""Tier-1 LLM triage: real provider calls with deterministic fallback.

Priority chain:
  1. LLMClient (Ollama → OpenAI → Anthropic depending on LLM_PROVIDER env).
  2. LocalDeterministicClient (hashes prompt; no external calls).
  3. Score-threshold fallback (if both clients are unavailable).

The LLM is asked for a JSON object:
  { "action": "ESCALATE|INVESTIGATE|NO_ACTION",
    "rationale": "<1-2 sentences>",
    "next_steps": ["...", "..."] }

If the LLM returns invalid JSON or times out, the score-threshold fallback
is used instead and `llm_provider` in the response will be 'fallback'.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.core.correlation.tier1_summarizer import summarize_tier1
from src.core.correlation.llm_prompt import build_tier1_prompt

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/api/v1/llm', tags=['llm'])


class LLMRequest(BaseModel):
    event: Dict[str, Any]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_client():
    """Return best available LLM client, never raises."""
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT
        return DEFAULT_CLIENT
    except Exception:
        pass
    try:
        from src.integrations.llm_client import LLMClient
        return LLMClient()
    except Exception:
        pass
    try:
        from src.integrations.llm_client import LocalDeterministicClient
        return LocalDeterministicClient()
    except Exception:
        return None


def _parse_llm_json(text: str) -> Dict[str, Any] | None:
    """Extract JSON object from LLM response text; handles markdown fences."""
    if not text:
        return None
    # Strip markdown code fences
    cleaned = re.sub(r'```(?:json)?', '', text).strip()
    # Find first { ... } block
    m = re.search(r'\{.*\}', cleaned, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def _deterministic_fallback(score: float) -> Dict[str, Any]:
    """Score-threshold fallback used when LLM is unavailable."""
    if score >= 0.8:
        return {
            'action': 'ESCALATE',
            'rationale': 'High-confidence indicators present; reply-to mismatch and multiple strong factors exceed threshold.',
            'next_steps': ['Block sender domain at tenant gateway', 'Open P1 incident and assign to analyst on-call'],
        }
    if score >= 0.5:
        return {
            'action': 'INVESTIGATE',
            'rationale': 'Moderate confidence; manual review of headers, attachments and authentication results recommended.',
            'next_steps': ['Verify SPF/DKIM/DMARC chain', 'Check display-name vs envelope-from mismatch'],
        }
    return {
        'action': 'NO_ACTION',
        'rationale': 'Low confidence; signals consistent with legitimate mail or already-whitelisted sender.',
        'next_steps': ['Record for baseline tuning', 'Monitor sender reputation'],
    }


def _call_llm(prompt: str, score: float) -> Dict[str, Any]:
    """Call LLM and parse response; falls back to deterministic on any error."""
    client = _get_client()
    provider_name = 'fallback'

    if client is not None:
        try:
            provider_name = getattr(client, 'provider', 'unknown')
            model_name = os.getenv('OLLAMA_TIER1_MODEL') or os.getenv('T1_MODEL') or None
            if model_name:
                result = client.generate(prompt, max_tokens=384, model=model_name)
            else:
                result = client.generate(prompt, max_tokens=384)
            text = result.get('text') or ''
            parsed = _parse_llm_json(text)
            if parsed and isinstance(parsed.get('action'), str) and parsed['action'].upper() in {
                'ESCALATE', 'INVESTIGATE', 'NO_ACTION', 'ACCEPT'
            }:
                return {
                    'action': parsed['action'].upper(),
                    'rationale': str(parsed.get('rationale') or ''),
                    'next_steps': list(parsed.get('next_steps') or []),
                    'llm_provider': provider_name,
                    'llm_raw': text[:500],
                }
            # LLM returned text but not valid JSON; try regex extraction
            action_m = re.search(r'\b(ESCALATE|INVESTIGATE|NO_ACTION|ACCEPT)\b', text, re.IGNORECASE)
            if action_m:
                action = action_m.group(1).upper()
                # Extract first sentence-like rationale after action keyword
                rationale = re.sub(r'^.*?' + action_m.group(1), '', text, flags=re.IGNORECASE).strip()
                rationale = (rationale[:200] or 'LLM response could not be fully parsed').strip()
                return {
                    'action': action,
                    'rationale': rationale,
                    'next_steps': [],
                    'llm_provider': provider_name,
                    'llm_raw': text[:500],
                    'parse_warning': 'json_parse_failed_used_regex',
                }
        except Exception as exc:
            logger.warning('Tier1 LLM call failed (%s): %s', provider_name, exc)

    fb = _deterministic_fallback(score)
    fb['llm_provider'] = 'fallback'
    return fb


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@router.post('/tier1/summarize', operation_id='llm_tier1_summarize')
async def llm_tier1_summarize(req: LLMRequest):
    """Tier-1 triage endpoint.

    Builds a context-rich prompt from the event, calls the configured LLM
    provider, and returns a structured triage decision.

    Response schema::

        {
          "action":        "ESCALATE|INVESTIGATE|NO_ACTION",
          "rationale":     "...",
          "next_steps":    ["...", "..."],
          "prompt":        "...",   // prompt sent to LLM (for auditability)
          "llm_provider":  "ollama|openai|anthropic|local-deterministic|fallback",
          "llm_raw":       "..."    // raw LLM text (first 500 chars) if available
        }
    """
    event = req.event

    # 1. Build deterministic Tier-1 summary (evidence manifest)
    if not event.get('tier1_summary'):
        try:
            event['tier1_summary'] = summarize_tier1(event)
        except Exception as exc:
            logger.error('summarize_tier1 failed: %s', exc)
            raise HTTPException(status_code=500, detail='failed to summarize')

    score = float(event['tier1_summary'].get('score') or 0.0)
    prompt = build_tier1_prompt(event['tier1_summary'], event)

    # 2. Call LLM (or fall back deterministically)
    decision = _call_llm(prompt, score)

    return {
        'action':       decision.get('action', 'INVESTIGATE'),
        'rationale':    decision.get('rationale', ''),
        'next_steps':   decision.get('next_steps', []),
        'prompt':       prompt,
        'llm_provider': decision.get('llm_provider', 'fallback'),
        'llm_raw':      decision.get('llm_raw', ''),
        'score':        score,
    }

