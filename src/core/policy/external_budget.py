"""External AI Budget Manager

Enforces per-tenant token usage budgets with soft and hard thresholds.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict

try:
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover
    Counter = None  # type: ignore
    Gauge = None    # type: ignore

@dataclass
class TenantBudget:
    soft_limit: int
    hard_limit: int
    window_seconds: int = 3600

class ExternalBudgetManager:
    def __init__(self):
        self._tenant_usage: dict[str, list[tuple[float,int]]] = {}
        self._tenant_budget: dict[str, TenantBudget] = {}
        self._init_metrics()

    def _init_metrics(self):
        if getattr(self.__class__,'_init', False):
            return
        try:
            if Counter:
                self.__class__.budget_denials = Counter('external_budget_denial_total','External AI budget denials',['reason'])
            if Gauge:
                self.__class__.tenant_token_usage = Gauge('external_ai_tokens_used','Rolling token usage per tenant',['tenant'])
        except Exception:
            pass
        self.__class__._init = True

    def configure_tenant(self, tenant: str, soft: int, hard: int, window_seconds: int = 3600):
        self._tenant_budget[tenant] = TenantBudget(soft, hard, window_seconds)

    def _prune(self, tenant: str):
        usage = self._tenant_usage.get(tenant, [])
        now = time.time()
        self._tenant_usage[tenant] = [(ts,t) for ts,t in usage if now - ts <= self._tenant_budget.get(tenant, TenantBudget(0,0)).window_seconds]

    def allow(self, tenant: str, projected_tokens: int) -> tuple[bool,str]:
        if tenant not in self._tenant_budget:
            return True, 'unconfigured'
        self._prune(tenant)
        budget = self._tenant_budget[tenant]
        used = sum(t for _,t in self._tenant_usage.get(tenant, []))
        new_total = used + projected_tokens
        reason = 'ok'
        if new_total > budget.hard_limit:
            reason = 'hard'
            self._record_denial(reason)
            return False, reason
        if new_total > budget.soft_limit:
            reason = 'soft'
            # still allow but mark reason
        return True, reason

    def commit(self, tenant: str, tokens: int):
        if tenant not in self._tenant_usage:
            self._tenant_usage[tenant] = []
        self._tenant_usage[tenant].append((time.time(), tokens))
        if hasattr(self.__class__, 'tenant_token_usage') and self.__class__.tenant_token_usage:
            try:
                self.__class__.tenant_token_usage.labels(tenant=tenant).set(sum(t for _,t in self._tenant_usage[tenant]))
            except Exception:
                pass

    def _record_denial(self, reason: str):
        if getattr(self.__class__, 'budget_denials', None):
            try: self.__class__.budget_denials.labels(reason=reason).inc()
            except Exception: pass

_global_budget: ExternalBudgetManager | None = None

def get_budget_manager() -> ExternalBudgetManager:
    global _global_budget
    if _global_budget is None:
        _global_budget = ExternalBudgetManager()
    return _global_budget
