from __future__ import annotations

import os
import json
from typing import Any

import requests


def _mock_summary(text: str, level: int = 1) -> str:
    if level == 1:
        return f"[Tier-1 Summary] {text[:140]}..."
    return f"[Tier-2 Detailed Summary] {text[:300]}..."


def _call_ollama(prompt: str, model: str = 'ggml-alloy', timeout: int = 10) -> str:
    host = os.getenv('OLLAMA_HOST') or os.getenv('OLLAMA_URL')
    if not host:
        raise RuntimeError('OLLAMA_HOST or OLLAMA_URL not set')
    # Prefer the v1 model-specific generate endpoint if available
    gen_path = f"/v1/models/{model}/generate"
    payload = {'prompt': prompt}
    r = requests.post(host.rstrip('/') + gen_path, json=payload, timeout=timeout)
    r.raise_for_status()
    try:
        data = r.json()
        # Ollama v1-style response may include 'object':'response' and 'data':[{'content':...}]
        if isinstance(data, dict):
            if 'content' in data:
                return data.get('content')
            if 'data' in data and isinstance(data['data'], list) and len(data['data'])>0:
                first = data['data'][0]
                if isinstance(first, dict) and 'content' in first:
                    return first['content']
        return json.dumps(data)
    except Exception:
        return r.text


def summarize_tier1(text: str) -> str:
    """Short, high-level summary for triage."""
    try:
        if os.getenv('USE_OLLAMA', '0') in {'1', 'true', 'yes'}:
            return _call_ollama(text, model=os.getenv('OLLAMA_MODEL', 'ggml-alloy'))
    except Exception:
        pass
    return _mock_summary(text, level=1)


def summarize_tier2(text: str) -> str:
    """Longer, contextual summary with suggested next steps."""
    try:
        if os.getenv('USE_OLLAMA', '0') in {'1', 'true', 'yes'}:
            return _call_ollama(text, model=os.getenv('OLLAMA_MODEL', 'ggml-alloy'))
    except Exception:
        pass
    return _mock_summary(text, level=2)
