from __future__ import annotations

import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Deque, Dict, Iterable, List, Optional

from .schemas import AlertSnapshot, DecisionRecord


@dataclass
class TenantMetrics:
    counts: Dict[str, int] = field(default_factory=lambda: {'allow': 0, 'deny': 0, 'quarantine': 0})
    heavy_ops: int = 0
    cost: float = 0.0
    event_times: Deque[float] = field(default_factory=deque)


class PlatformState:
    """In-memory decision cache and tenant metrics store."""

    def __init__(
        self,
        cache_size: int = 5000,
        alert_max: int = 500,
        cost_per_event: float = 0.001,
        cost_heavy_event: float = 0.01,
        rollup_window_seconds: int = 300,
    ) -> None:
        self.cache_size = cache_size
        self.alert_max = alert_max
        self.cost_per_event = cost_per_event
        self.cost_heavy_event = cost_heavy_event
        self.rollup_window = rollup_window_seconds

        self._lock = Lock()
        self._decisions: "OrderedDict[str, DecisionRecord]" = OrderedDict()
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=alert_max)
        self._tenants: Dict[str, TenantMetrics] = {}

    def record_decision(self, decision: DecisionRecord, heavy: bool) -> None:
        tenant_id = decision.tenant_id or 'public'
        with self._lock:
            if decision.event_id in self._decisions:
                self._decisions.pop(decision.event_id)
            self._decisions[decision.event_id] = decision
            while len(self._decisions) > self.cache_size:
                self._decisions.popitem(last=False)

            metrics = self._tenants.setdefault(tenant_id, TenantMetrics())
            metrics.counts[decision.verdict] = metrics.counts.get(decision.verdict, 0) + 1
            metrics.event_times.append(decision.timestamp)
            self._prune_old(metrics.event_times)
            if heavy:
                metrics.heavy_ops += 1
                metrics.cost += self.cost_heavy_event
            else:
                metrics.cost += self.cost_per_event

            if decision.verdict != 'allow':
                self._alerts.append({
                    'id': decision.event_id,
                    'verdict': decision.verdict,
                    'confidence': decision.confidence,
                    'factors': decision.factors,
                    'tenant_id': tenant_id,
                    'ts': decision.timestamp,
                })

    def aggregate_metrics(self) -> Dict[str, float]:
        with self._lock:
            totals = {'allow': 0, 'deny': 0, 'quarantine': 0}
            heavy = 0
            cost = 0.0
            for metrics in self._tenants.values():
                for key in totals.keys():
                    totals[key] += metrics.counts.get(key, 0)
                heavy += metrics.heavy_ops
                cost += metrics.cost
        return {
            'decisions': totals,
            'heavy_ops': heavy,
            'realized_cost': round(cost, 6),
        }

    def tenant_metrics(self, tenant_id: str) -> Dict[str, float]:
        with self._lock:
            metrics = self._tenants.get(tenant_id, TenantMetrics())
            event_times = deque(metrics.event_times)
        eps = self._events_per_second(event_times)
        return {
            'tenant': tenant_id,
            'decisions': metrics.counts.copy(),
            'heavy_ops': metrics.heavy_ops,
            'realized_cost': round(metrics.cost, 6),
            'eps_recent': round(eps, 3),
        }

    def debug_state(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'alert_ring_size': len(self._alerts),
                'decision_cache_size': len(self._decisions),
                'tenants': list(self._tenants.keys()),
            }

    def recent_alerts(self, limit: int = 50, tenant_id: str | None = None) -> List[AlertSnapshot]:
        with self._lock:
            snapshots = list(self._alerts)
            if tenant_id:
                snapshots = [entry for entry in snapshots if entry.get('tenant_id') == tenant_id]
            snapshots = snapshots[-limit:]
        return [AlertSnapshot(**entry) for entry in snapshots]

    def _prune_old(self, times: Deque[float]) -> None:
        cutoff = time.time() - self.rollup_window
        while times and times[0] < cutoff:
            times.popleft()

    def _events_per_second(self, times: Iterable[float]) -> float:
        items = list(times)
        if len(items) < 2:
            return 0.0
        span = items[-1] - items[0]
        if span <= 0:
            return float(len(items))
        return len(items) / span
