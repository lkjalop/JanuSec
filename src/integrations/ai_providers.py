"""AI Provider Adapters (Airia / Neuron)

Provides unified interface for external AI enrichment tiers with:
- Token rotation
- Mock mode for synthetic tests
- Cost ledger integration hook
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    # Prefer unified import path with tests to ensure singleton consistency
    from src.core.metrics.cost_ledger import get_cost_ledger  # type: ignore
except Exception:  # fallback to legacy path
    from core.metrics.cost_ledger import get_cost_ledger  # type: ignore
from core.policy.external_budget import get_budget_manager


@dataclass
class ProviderConfig:
    name: str
    api_keys: list[str]
    mock: bool = False
    latency_ms_range: tuple[int,int] = (400, 1200)
    model: str = 'default'

class AIProviderBase:
    def __init__(self, cfg: ProviderConfig):
        self.cfg = cfg
        self._idx = 0

    def _next_key(self) -> str | None:
        if not self.cfg.api_keys:
            return None
        key = self.cfg.api_keys[self._idx % len(self.cfg.api_keys)]
        self._idx += 1
        return key

    async def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - network placeholder
        start = time.perf_counter()
        if self.cfg.mock:
            # Simulate latency & result
            lo, hi = self.cfg.latency_ms_range
            simulated = random.randint(lo, hi) / 1000.0
            await self._sleep(simulated)
            res = {
                'success': True,
                'model': self.cfg.model,
                'confidence': round(random.uniform(0.6, 0.95), 3),
                'tokens_used': random.randint(150, 600),
                'enrichment': {'summary': 'mocked', 'iocs': []}
            }
        else:
            # Placeholder real call
            await self._sleep(1.0)
            res = {
                'success': True,
                'model': self.cfg.model,
                'confidence': 0.8,
                'tokens_used': 300,
                'enrichment': {'summary': 'real-call-placeholder'}
            }
        dur_ms = (time.perf_counter() - start) * 1000
        tokens = res.get('tokens_used',0)
        # Budget manager enforcement (tenant optional in payload)
        tenant = payload.get('tenant','default')
        bm = get_budget_manager()
        allow, reason = bm.allow(tenant, tokens)
        res['budget_reason'] = reason
        if not allow:
            res['success'] = False
            res['error'] = f"budget_denied:{reason}"
            res['latency_ms'] = dur_ms
            return res
        bm.commit(tenant, tokens)
        # Record to the unified cost ledger using the expected signature:
        # record(tier: str, path: str, start: float, tokens: int = 0, ...)
        try:
            get_cost_ledger().record("external_ai", self.cfg.model or 'external', start, tokens=tokens, cached=False, success=True, tenant=tenant)
        except Exception:
            # Best-effort: don't fail the provider call if ledger recording has issues
            pass
        res['latency_ms'] = dur_ms
        return res

    async def _sleep(self, secs: float):  # isolated for potential fast-forward in tests
        import asyncio
        await asyncio.sleep(secs)

class AiriaProvider(AIProviderBase):
    pass

class NeuronProvider(AIProviderBase):
    pass

_provider_singletons: dict[str, AIProviderBase] = {}

def get_provider(name: str, cfg: ProviderConfig) -> AIProviderBase:
    key = f"{name}:{cfg.model}:{cfg.mock}:{len(cfg.api_keys)}"
    if key not in _provider_singletons:
        if name.lower() == 'airia':
            _provider_singletons[key] = AiriaProvider(cfg)
        elif name.lower() == 'neuron':
            _provider_singletons[key] = NeuronProvider(cfg)
        else:
            _provider_singletons[key] = AIProviderBase(cfg)
    return _provider_singletons[key]
