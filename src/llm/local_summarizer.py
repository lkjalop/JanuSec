from __future__ import annotations

import os
import json
from typing import Any

import requests


def _mock_summary(text: str, level: int = 1) -> str:
    if level == 1:
        return f"[Tier-1 Summary] {text[:140]}..."
    return f"[Tier-2 Detailed Summary] {text[:300]}..."


def _call_ollama(prompt: str, model: str = 'llama3.2:3b', timeout: int = 45) -> str:
    host = os.getenv('OLLAMA_HOST') or os.getenv('OLLAMA_URL') or 'http://localhost:11434'
    # Use the standard Ollama generate API
    payload = {'model': model, 'prompt': prompt, 'stream': False}
    r = requests.post(host.rstrip('/') + '/api/generate', json=payload, timeout=timeout)
    r.raise_for_status()
    try:
        data = r.json()
        if isinstance(data, dict):
            return data.get('response') or data.get('content') or json.dumps(data)
        return json.dumps(data)
    except Exception:
        return r.text


def summarize_tier1(text: str) -> str:
    """Short, high-level summary for triage."""
    if os.getenv('LLM_MOCK', '0').lower() in {'1', 'true', 'yes'}:
        return _mock_summary(text, level=1)
    try:
        model = os.getenv('T1_MODEL') or os.getenv('OLLAMA_MODEL', 'llama3.2:3b')
        return _call_ollama(text, model=model)
    except Exception:
        return _mock_summary(text, level=1)


def summarize_tier2(text: str) -> str:
    """Longer, contextual summary with suggested next steps."""
    if os.getenv('LLM_MOCK', '0').lower() in {'1', 'true', 'yes'}:
        return _mock_summary(text, level=2)
    try:
        model = os.getenv('T2_MODEL') or os.getenv('OLLAMA_MODEL', 'llama3.2:3b')
        timeout = int(os.getenv('OLLAMA_TIMEOUT_SECONDS') or os.getenv('LLM_TIMEOUT_SECONDS') or '45')
        return _call_ollama(text, model=model, timeout=timeout)
    except Exception:
        return _mock_summary(text, level=2)
