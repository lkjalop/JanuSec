"""
LLM Model Catalog
=================
GET /api/v1/llm/models/catalog — returns available + disabled model entries
for the shared UI model picker used by the cluster Summarise button and
CRAG + LLM Enrich panel.

Response shape per entry:
  {
    id:             str,    # model identifier passed to the LLM client
    label:          str,    # human-readable label for <select> options
    provider:       str,    # "ollama" | "openai" | "anthropic"
    tier:           str,    # "local" | "cloud"
    configured:     bool,   # API key / service is present
    available:      bool,   # reachable right now
    disabled_reason: str|None,  # shown greyed-out when not available
    source:         str,    # "ollama_live" | "fallback" | "catalog"
    recommended:    bool,   # currently configured default
  }
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import APIRouter

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/api/v1/llm', tags=['llm-catalog'])

# Ordered list of known public / cloud API models shown as disabled when the
# corresponding API key is absent.  Add new providers here as they become
# supported by llm_client.py.
_PUBLIC_MODELS = [
    {
        'id':      'claude-sonnet-4-6',
        'label':   'Claude Sonnet 4.6 — Anthropic ⭐',
        'provider': 'anthropic',
        'key_env': 'ANTHROPIC_API_KEY',
    },
    {
        'id':      'claude-opus-4-6',
        'label':   'Claude Opus 4.6 — Anthropic',
        'provider': 'anthropic',
        'key_env': 'ANTHROPIC_API_KEY',
    },
    {
        'id':      'claude-sonnet-4-5',
        'label':   'Claude Sonnet 4.5 — Anthropic',
        'provider': 'anthropic',
        'key_env': 'ANTHROPIC_API_KEY',
    },
    {
        'id':      'gpt-4o',
        'label':   'GPT-4o — OpenAI',
        'provider': 'openai',
        'key_env': 'OPENAI_API_KEY',
    },
    {
        'id':      'gpt-4o-mini',
        'label':   'GPT-4o Mini — OpenAI',
        'provider': 'openai',
        'key_env': 'OPENAI_API_KEY',
    },
]

# Well-known local Ollama models used as placeholders when Ollama is offline.
_FALLBACK_LOCAL_MODELS = [
    'qwen3:30b',
    'qwen3:14b',
    'mistral-small3.2:24b',
    'qwen2.5:14b',
    'qwen2.5:7b',
    'llama3.2:3b',
    'mistral:7b',
    'deepseek-r1:8b',
]


@router.get('/models/catalog')
async def get_model_catalog(tenant_id: Optional[str] = 'default') -> dict:
    """Return model options for the shared UI model picker.

    Query params:
      tenant_id — reserved; currently not used for per-tenant filtering.
    """
    entries: list[dict] = []

    # ── Local Ollama models ───────────────────────────────────────────────────
    ollama_live: list[str] = []
    configured_default    = os.getenv('OLLAMA_MODEL', 'qwen3:14b')
    ollama_host           = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
    ollama_reachable      = False

    try:
        from src.integrations.llm_client import DEFAULT_CLIENT as _LLM  # type: ignore
        if _LLM:
            configured_default = getattr(_LLM, 'ollama_model', None) or configured_default
            ollama_host        = getattr(_LLM, 'ollama_host', None)  or ollama_host
    except Exception as exc:
        logger.debug('model catalog: llm_client import failed: %s', exc)

    # Probe Ollama directly — don't depend on session state from llm_client.
    import requests as _req
    for _path, _key in [('/api/tags', 'models'), ('/v1/models', 'data'), ('/v1/models', 'models')]:
        try:
            r = _req.get(f'{ollama_host}{_path}', timeout=4.0)
            if r.status_code == 200:
                data  = r.json()
                items = data.get(_key) or []
                for m in items:
                    mid = m.get('name') or m.get('id') or m.get('model') or ''
                    if mid and mid not in ollama_live:
                        ollama_live.append(mid)
                ollama_reachable = True
                break
        except Exception as exc:
            logger.debug('model catalog: Ollama probe %s failed: %s', _path, exc)

    # Add live Ollama models in the order returned by Ollama.
    seen: set[str] = set()
    for mid in ollama_live:
        seen.add(mid)
        entries.append({
            'id':             mid,
            'label':          mid,
            'provider':       'ollama',
            'tier':           'local',
            'configured':     True,
            'available':      True,
            'disabled_reason': None,
            'source':         'ollama_live',
            'recommended':    mid == configured_default,
        })

    # When Ollama is offline, surface known-fallback models as greyed-out so
    # the analyst sees *something* rather than an empty dropdown.
    if not ollama_reachable:
        for mid in _FALLBACK_LOCAL_MODELS:
            if mid in seen:
                continue
            seen.add(mid)
            entries.append({
                'id':             mid,
                'label':          mid + ' (Ollama offline)',
                'provider':       'ollama',
                'tier':           'local',
                'configured':     False,
                'available':      False,
                'disabled_reason': 'Ollama is not reachable — start Ollama and reload.',
                'source':         'fallback',
                'recommended':    False,
            })

    # ── Public / cloud API models ─────────────────────────────────────────────
    openai_key    = ''
    anthropic_key = ''
    try:
        from src.integrations.llm_client import DEFAULT_CLIENT as _LLM  # type: ignore
        if _LLM:
            openai_key    = getattr(_LLM, 'openai_key', '')    or ''
            anthropic_key = getattr(_LLM, 'anthropic_key', '') or ''
    except Exception:
        pass
    openai_key    = openai_key    or os.getenv('OPENAI_API_KEY', '')
    anthropic_key = anthropic_key or os.getenv('ANTHROPIC_API_KEY', '')

    key_map = {'openai': openai_key, 'anthropic': anthropic_key}

    for pm in _PUBLIC_MODELS:
        configured_flag = bool(key_map.get(pm['provider'], ''))
        entries.append({
            'id':              pm['id'],
            'label':           pm['label'],
            'provider':        pm['provider'],
            'tier':            'cloud',
            'configured':      configured_flag,
            'available':       configured_flag,
            'disabled_reason': None if configured_flag else f"{pm['key_env']} not configured",
            'source':          'catalog',
            'recommended':     False,
        })

    return {
        'models':         entries,
        'ollama_reachable': ollama_reachable,
        'ollama_host':    ollama_host,
        'default_model':  configured_default,
    }
