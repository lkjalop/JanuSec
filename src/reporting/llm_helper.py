import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional

from src.integrations.llm_client import generate_summary
from .prompt_templates import build_incident_prompt

CACHE_DIR = Path(os.getenv('LLM_PROMPT_CACHE_DIR', 'data/llm_cache'))
CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _prompt_to_string(prompt_obj: Dict[str, Any]) -> str:
    # Build a reproducible string representation from messages
    msgs = prompt_obj.get('messages') or []
    s = '\n'.join([f"{m.get('role')}: {m.get('content')}" for m in msgs])
    return s


def cached_generate(persona: str, incident: Dict[str, Any], examples: Optional[list] = None, temperature: Optional[float] = None, use_cache: bool = True) -> Dict[str, Any]:
    prompt_obj = build_incident_prompt(persona, incident, examples=examples, temperature=temperature)
    prompt_text = _prompt_to_string(prompt_obj)
    h = hashlib.sha256(prompt_text.encode('utf-8')).hexdigest()
    cache_path = CACHE_DIR / f"{h}.json"
    if use_cache and cache_path.exists():
        try:
            with open(cache_path, 'r', encoding='utf-8') as fh:
                return json.load(fh)
        except Exception:
            pass
    # Call LLM client
    res = generate_summary(prompt_text, max_tokens=512)
    out = {
        'prompt_hash': h,
        'persona': persona,
        'prompt_preview': prompt_text[:2000],
        'response': res,
    }
    try:
        with open(cache_path, 'w', encoding='utf-8') as fh:
            json.dump(out, fh, indent=2)
    except Exception:
        pass
    return out
