from __future__ import annotations

import time
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Deque, Dict, List, Optional

from .schemas import AlertSnapshot, DecisionRecord


@dataclass
class TenantMetrics:
    counts: dict[str, int] = field(default_factory=lambda: {'allow': 0, 'deny': 0, 'quarantine': 0})
    heavy_ops: int = 0
    cost: float = 0.0
    event_times: deque[float] = field(default_factory=deque)


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
        self._decisions: OrderedDict[str, DecisionRecord] = OrderedDict()
        self._alerts: deque[dict[str, Any]] = deque(maxlen=alert_max)
        self._tenants: dict[str, TenantMetrics] = {}

    def record_decision(self, decision: DecisionRecord, heavy: bool) -> None:
        tenant_id = decision.tenant_id or 'public'
        alert_payload: dict[str, Any] | None = None
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
                alert_payload = {
                    'id': decision.event_id,
                    'verdict': decision.verdict,
                    'confidence': decision.confidence,
                    'factors': decision.factors,
                    'correlation_insights': getattr(decision, 'correlation_insights', []),
                    'tenant_id': tenant_id,
                    'ts': decision.timestamp,
                }
        if alert_payload:
            appended = False
            try:
                from .alerts_endpoints import append_alert  # type: ignore circular
                append_alert(alert_payload)
                appended = True
            except Exception:
                appended = False
            if not appended:
                with self._lock:
                    self._alerts.append(alert_payload)

    def aggregate_metrics(self) -> dict[str, float]:
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

    def tenant_metrics(self, tenant_id: str) -> dict[str, float]:
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

    def debug_state(self) -> dict[str, Any]:
        with self._lock:
            return {
                'alert_ring_size': len(self._alerts),
                'decision_cache_size': len(self._decisions),
                'tenants': list(self._tenants.keys()),
            }

    def recent_alerts(self, limit: int = 50, tenant_id: str | None = None) -> list[AlertSnapshot]:
        with self._lock:
            snapshots = list(self._alerts)
            if tenant_id:
                snapshots = [entry for entry in snapshots if entry.get('tenant_id') == tenant_id]
            snapshots = snapshots[-limit:]
        normalized: list[dict[str, Any]] = []
        now = time.time()
        for idx, entry in enumerate(snapshots):
            data = dict(entry)
            alert_id = data.get('id') or data.get('event_id')
            if not alert_id:
                base_ts = data.get('ts') or data.get('timestamp') or now
                try:
                    base_ts = float(base_ts)
                except Exception:
                    base_ts = now
                alert_id = f"alert-{int(base_ts)}-{idx}"
            data['id'] = str(alert_id)
            verdict = data.get('verdict') or data.get('severity') or 'suspicious'
            data['verdict'] = str(verdict)
            confidence = data.get('confidence')
            if confidence is None:
                confidence = data.get('score')
            try:
                data['confidence'] = float(confidence) if confidence is not None else 0.5
            except Exception:
                data['confidence'] = 0.5
            factors = data.get('factors')
            if isinstance(factors, list):
                data['factors'] = factors
            elif factors is None:
                data['factors'] = []
            elif isinstance(factors, str):
                data['factors'] = [factors]
            else:
                try:
                    data['factors'] = list(factors)
                except Exception:
                    data['factors'] = []
            tenant = data.get('tenant_id') or data.get('tenant') or 'default'
            data['tenant_id'] = str(tenant) if tenant is not None else 'default'
            ts_val = data.get('ts') or data.get('timestamp')
            if ts_val is None:
                ts_val = now
            try:
                data['ts'] = float(ts_val)
            except Exception:
                data['ts'] = now
            normalized.append(data)
        return [AlertSnapshot(**entry) for entry in normalized]

    def _prune_old(self, times: deque[float]) -> None:
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
