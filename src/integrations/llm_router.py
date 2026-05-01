"""LLM tier router — maps CRAG grade + cluster severity to the right model.

Routing table
─────────────
CRAG REJECT              → caller should not invoke this module (no LLM)
CRAG REFINE, sev low/med → tier 'small'    (fast local model)
CRAG ACCEPT,  sev high   → tier 'large'    (larger local or cheap API)
CRAG ACCEPT,  sev crit   → tier 'critical' (frontier API / cloud-native)

The router returns a `CallSpec` that cluster_enrich_endpoints feeds directly
into DEFAULT_CLIENT.generate(overrides=...).  It never instantiates a second
LLMClient — it just shapes the overrides dict so the existing client knows
which provider/model/key to use for this call.

Fallback chain (when tenant has no config):
  critical → env ANTHROPIC_API_KEY or OPENAI_API_KEY (if set) → ollama large
  large    → ollama large (OLLAMA_MODEL_LARGE env) → ollama default
  small    → ollama default (OLLAMA_MODEL env)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Severity / CRAG composite thresholds ────────────────────────────────────

_CRAG_LARGE_THRESHOLD    = float(os.getenv('LLM_ROUTER_LARGE_THRESHOLD',    '0.72'))
_CRAG_CRITICAL_THRESHOLD = float(os.getenv('LLM_ROUTER_CRITICAL_THRESHOLD', '0.85'))

_SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


def _pick_tier(crag_composite: float, crag_verdict: str, severity: str) -> str:
    """Return 'small' | 'large' | 'critical'."""
    sev_rank = _SEV_RANK.get((severity or '').lower(), 1)
    # Critical tier: composite ≥ threshold OR explicit critical severity
    if crag_composite >= _CRAG_CRITICAL_THRESHOLD or sev_rank >= 4:
        return 'critical'
    # Large tier: composite ≥ threshold OR high severity
    if crag_composite >= _CRAG_LARGE_THRESHOLD or sev_rank >= 3:
        return 'large'
    return 'small'


# ── CallSpec ────────────────────────────────────────────────────────────────

@dataclass
class CallSpec:
    """Everything needed for one LLM call.  Fed into DEFAULT_CLIENT.generate()."""
    tier: str                          # 'small' | 'large' | 'critical'
    provider: str                      # 'ollama' | 'anthropic' | 'openai' | 'bedrock' | …
    model: str                         # model ID for this call
    overrides: Dict[str, Any] = field(default_factory=dict)
    thinking_budget: int = 0           # 0 = disabled
    max_tokens: int = 2048
    # Human-readable explanation for logs/UI
    routing_reason: str = ''


# ── Global fallback (no tenant config) ──────────────────────────────────────

def _global_fallback_spec(tier: str, thinking_budget: int) -> CallSpec:
    """Build a CallSpec from env vars when no per-tenant config exists."""

    # Check for managed API keys in env
    anthropic_key = os.getenv('ANTHROPIC_API_KEY', '')
    openai_key    = os.getenv('OPENAI_API_KEY', '')

    # Tier → model env vars (operators can override per-tier without tenant config).
    # Use env vars only — do NOT read DEFAULT_CLIENT.ollama_model here because
    # DEFAULT_CLIENT may have been initialised before the .env was loaded, leaving
    # stale values (e.g. llama3:8b) that would override what the operator set.
    _default_model = 'qwen3:14b'
    _default_host  = 'http://127.0.0.1:11434'

    ollama_small    = os.getenv('OLLAMA_MODEL_SMALL')    or os.getenv('OLLAMA_MODEL') or _default_model
    ollama_large    = os.getenv('OLLAMA_MODEL_LARGE')    or os.getenv('OLLAMA_MODEL') or _default_model
    ollama_critical = os.getenv('OLLAMA_MODEL_CRITICAL') or os.getenv('OLLAMA_MODEL') or _default_model
    ollama_host     = os.getenv('OLLAMA_HOST', _default_host).rstrip('/')

    if tier == 'small':
        return CallSpec(
            tier=tier,
            provider='ollama',
            model=ollama_small,
            overrides={'ollama_host': ollama_host, 'ollama_model': ollama_small},
            thinking_budget=0,
            max_tokens=1536,
            routing_reason=f'global-fallback: small tier → ollama/{ollama_small}',
        )

    if tier == 'large':
        return CallSpec(
            tier=tier,
            provider='ollama',
            model=ollama_large,
            overrides={'ollama_host': ollama_host, 'ollama_model': ollama_large},
            thinking_budget=min(thinking_budget, 2048) if thinking_budget else 1024,
            max_tokens=3072,
            routing_reason=f'global-fallback: large tier → ollama/{ollama_large}',
        )

    # critical — prefer managed keys, fall back to local
    if anthropic_key:
        # Operators can opt into newer Sonnet/Opus releases by setting
        # ANTHROPIC_MODEL_CRITICAL. Keep the default on a stable dated API ID.
        model = os.getenv('ANTHROPIC_MODEL_CRITICAL', 'claude-sonnet-4-6')
        return CallSpec(
            tier=tier,
            provider='anthropic',
            model=model,
            overrides={'anthropic_key': anthropic_key, 'provider': 'anthropic'},
            thinking_budget=thinking_budget or 4096,
            max_tokens=min(thinking_budget + 1024, 8192) if thinking_budget else 5120,
            routing_reason=f'global-fallback: critical tier → anthropic/{model} (env key)',
        )
    if openai_key:
        model = os.getenv('OPENAI_MODEL_CRITICAL', 'gpt-4o')
        return CallSpec(
            tier=tier,
            provider='openai',
            model=model,
            overrides={'openai_key': openai_key, 'provider': 'openai'},
            thinking_budget=0,
            max_tokens=4096,
            routing_reason=f'global-fallback: critical tier → openai/{model} (env key)',
        )
    # No managed key — use local critical model
    return CallSpec(
        tier=tier,
        provider='ollama',
        model=ollama_critical,
        overrides={'ollama_host': ollama_host, 'ollama_model': ollama_critical},
        thinking_budget=min(thinking_budget, 4096) if thinking_budget else 2048,
        max_tokens=4096,
        routing_reason=f'global-fallback: critical tier → ollama/{ollama_critical} (no API key)',
    )


# ── Per-tenant spec ──────────────────────────────────────────────────────────

def _tenant_spec(
    tier: str,
    thinking_budget: int,
    tenant_id: str,
) -> Optional[CallSpec]:
    """Load tenant config and build a CallSpec.  Returns None if no tenant config."""
    try:
        from src.core.config.tenant_llm_config import load_tenant_llm_config
        cfg = load_tenant_llm_config(tenant_id)
    except Exception:
        return None
    if cfg is None or not cfg.enabled:
        return None

    model = cfg.model_for_tier(tier)
    api_key = cfg.get_api_key()
    provider = cfg.provider

    overrides: Dict[str, Any] = {'provider': provider}

    if provider == 'ollama':
        overrides['ollama_host']  = cfg.ollama_host or 'http://127.0.0.1:11434'
        overrides['ollama_model'] = model
        tb = 0  # Ollama thinking via overrides handled separately
    elif provider == 'anthropic':
        if api_key:
            overrides['anthropic_key'] = api_key
        tb = thinking_budget or (4096 if tier == 'critical' else 1024)
    elif provider == 'openai':
        if api_key:
            overrides['openai_key'] = api_key
        tb = 0
    elif provider == 'bedrock':
        overrides['bedrock_region'] = cfg.region or 'us-east-1'
        overrides['bedrock_model']  = model
        # Bedrock uses IAM role — no key in overrides
        tb = thinking_budget or (4096 if tier == 'critical' else 1024)
    elif provider == 'azure_openai':
        overrides['azure_endpoint']    = cfg.endpoint
        overrides['azure_api_version'] = os.getenv('AZURE_OPENAI_API_VERSION', '2024-12-01-preview')
        if api_key:
            overrides['azure_api_key'] = api_key
        tb = 0
    elif provider == 'vertex':
        overrides['vertex_project'] = os.getenv('VERTEX_PROJECT', '')
        overrides['vertex_location'] = cfg.region or os.getenv('VERTEX_LOCATION', 'us-central1')
        tb = 0
    else:
        logger.warning('llm_router: unknown provider %r for tenant %s', provider, tenant_id)
        return None

    max_tokens = _max_tokens_for_tier(tier, tb)
    return CallSpec(
        tier=tier,
        provider=provider,
        model=model,
        overrides=overrides,
        thinking_budget=tb,
        max_tokens=max_tokens,
        routing_reason=f'tenant:{tenant_id} tier:{tier} → {provider}/{model}',
    )


def _max_tokens_for_tier(tier: str, thinking_budget: int) -> int:
    base = {
        'small':    1536,
        'large':    3072,
        'critical': 5120,
    }.get(tier, 2048)
    if thinking_budget > 0:
        return min(thinking_budget + 1024, 8192)
    return base


# ── Public API ───────────────────────────────────────────────────────────────

def route(
    crag_grade: Dict[str, Any],
    cluster_severity: str,
    tenant_id: str,
    thinking_budget: int = 0,
) -> CallSpec:
    """Return the CallSpec to use for this enrichment call.

    Args:
        crag_grade:       Result dict from grade_cluster() — needs 'verdict' + 'composite'.
        cluster_severity: Cluster severity string ('critical'|'high'|'medium'|'low').
        tenant_id:        Tenant identifier — used to load per-tenant config.
        thinking_budget:  Requested extended-thinking token budget (0 = use tier default).

    Raises:
        ValueError: if CRAG verdict is REJECT (caller must not call LLM).
    """
    verdict   = (crag_grade.get('verdict') or '').upper()
    composite = float(crag_grade.get('composite') or 0.0)

    if verdict == 'REJECT':
        raise ValueError(
            f'CRAG verdict is REJECT (composite={composite:.3f}) — '
            'LLM call blocked.  Collect more telemetry before enriching.'
        )

    tier = _pick_tier(composite, verdict, cluster_severity)

    # Try per-tenant config first
    spec = _tenant_spec(tier, thinking_budget, tenant_id)
    if spec is not None:
        logger.info('llm_router: %s', spec.routing_reason)
        return spec

    # Fall back to global env-based routing
    spec = _global_fallback_spec(tier, thinking_budget)
    logger.info('llm_router: %s', spec.routing_reason)
    return spec


def describe_routing(
    crag_grade: Dict[str, Any],
    cluster_severity: str,
    tenant_id: str,
) -> Dict[str, Any]:
    """Return routing decision metadata for UI display (does NOT call LLM)."""
    verdict   = (crag_grade.get('verdict') or '').upper()
    composite = float(crag_grade.get('composite') or 0.0)
    if verdict == 'REJECT':
        return {
            'verdict': 'REJECT',
            'tier': None,
            'provider': None,
            'model': None,
            'llm_blocked': True,
            'reason': 'CRAG verdict REJECT — evidence too thin for LLM enrichment.',
        }
    tier = _pick_tier(composite, verdict, cluster_severity)
    spec = _tenant_spec(tier, 0, tenant_id) or _global_fallback_spec(tier, 0)
    return {
        'verdict': verdict,
        'tier': tier,
        'provider': spec.provider,
        'model': spec.model,
        'llm_blocked': False,
        'reason': spec.routing_reason,
    }


__all__ = ['CallSpec', 'route', 'describe_routing']
