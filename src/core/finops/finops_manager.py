"""FinOps Manager (Option B + D pattern)

Consumes cost ledger events via subscription callback and produces:
- Hourly & daily rollups per (tenant, component)
- Simple monthly forecast using rolling daily average
- Estimation error tracking
- Prometheus metrics (if client present)

Future extensions:
- Cost anomaly detection
- Per-tenant budget policies (persisted)
- ML-based forecasting
"""
from __future__ import annotations

import math
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Dict, Tuple

try:
    from prometheus_client import Counter, Gauge
except Exception:  # pragma: no cover
    Counter = None  # type: ignore
    Gauge = None    # type: ignore

@dataclass
class CostEvent:
    ts: float
    tenant: str
    component: str
    units: float
    cost_units: float
    meta: dict[str, Any]

class FinOpsManager:
    def __init__(self):
        self._lock = threading.Lock()
        # Raw events (recent window only for memory safety)
        self._recent: deque[CostEvent] = deque(maxlen=50000)
        # Hourly rollup: {(tenant,component,hour_epoch)->cost_units}
        self._hourly: dict[tuple[str,str,int], float] = defaultdict(float)
        # Daily rollup: {(tenant,component,day_epoch)->cost_units}
        self._daily: dict[tuple[str,str,int], float] = defaultdict(float)
        # Estimation tracking
        self._estimates: dict[str, tuple[float,float]] = {}  # id -> (est, actual)
        self._estimate_history: deque[tuple[str,float,float,float]] = deque(maxlen=200)  # (id, est, actual, ts)
        self._init_metrics()

    def _init_metrics(self):
        if getattr(self.__class__,'_init', False):
            return
        if Gauge:
            try:
                self.__class__.g_hourly = Gauge('finops_cost_units_hourly','Hourly cost units',{ 'tenant':'','component':'' }) # placeholder pattern
            except Exception:
                pass
        if Counter:
            try:
                self.__class__.c_events = Counter('finops_cost_events_total','FinOps cost events ingested',['tenant','component'])
                self.__class__.c_estimation = Counter('finops_estimation_records_total','FinOps estimation records',['status'])
            except Exception:
                pass
        self.__class__._init = True

    def ingest(self, tenant: str, component: str, cost_units: float, units: float, meta: dict[str,Any] | None = None):
        now = time.time()
        evt = CostEvent(now, tenant, component, units, cost_units, meta or {})
        hour_epoch = int(now // 3600 * 3600)
        day_epoch = int(now // 86400 * 86400)
        with self._lock:
            self._recent.append(evt)
            self._hourly[(tenant,component,hour_epoch)] += cost_units
            self._daily[(tenant,component,day_epoch)] += cost_units
            if getattr(self.__class__,'c_events', None):
                try: self.__class__.c_events.labels(tenant=tenant, component=component).inc()
                except Exception: pass

    def record_estimate(self, estimate_id: str, estimated: float, actual: float):
        with self._lock:
            self._estimates[estimate_id] = (estimated, actual)
            self._estimate_history.append((estimate_id, estimated, actual, time.time()))
            status = 'ok'
            if estimated == 0:
                status = 'zero_est'
            else:
                err_ratio = abs(actual - estimated)/estimated
                if err_ratio > 0.5: status = 'high_error'
            if getattr(self.__class__,'c_estimation', None):
                try: self.__class__.c_estimation.labels(status=status).inc()
                except Exception: pass

    def hourly_summary(self, tenant: str | None = None) -> dict[str, Any]:
        now = time.time()
        cut = now - 3600*24
        with self._lock:
            rows = [((t,c,h),v) for (t,c,h),v in self._hourly.items() if h >= int(cut //3600 *3600) and (tenant is None or t==tenant)]
        return {'hours': [ {'tenant':t,'component':c,'hour':h,'cost_units':v} for (t,c,h),v in sorted(rows)]}

    def daily_summary(self, tenant: str | None = None) -> dict[str, Any]:
        now = time.time()
        cut = now - 86400*30
        with self._lock:
            rows = [((t,c,d),v) for (t,c,d),v in self._daily.items() if d >= int(cut //86400 *86400) and (tenant is None or t==tenant)]
        return {'days': [ {'tenant':t,'component':c,'day':d,'cost_units':v} for (t,c,d),v in sorted(rows)]}

    def forecast_month(self, tenant: str) -> dict[str, Any]:
        # Simple: average daily over last N days * days_in_month
        ds = self.daily_summary(tenant)['days']
        if not ds:
            return {'tenant':tenant,'forecast_units':0,'basis_days':0}
        # Keep last up to 14 days
        last = ds[-14:]
        avg = sum(d['cost_units'] for d in last)/len(last)
        # Approx days in month (30) for MVP
        forecast = avg * 30
        return {'tenant':tenant,'forecast_units':round(forecast,2),'basis_days':len(last),'avg_daily':round(avg,2)}

    def accuracy_history(self, limit: int = 30) -> dict[str, Any]:
        with self._lock:
            rows = list(self._estimate_history)[-limit:]
        out = []
        for sid, est, act, ts in rows:
            delta = act - est
            pct = (delta/est*100.0) if est else None
            out.append({'session_id': sid, 'estimate': est, 'actual': act, 'delta': delta, 'delta_pct': round(pct,2) if pct is not None else None, 'timestamp': ts})
        return {'history': out}

# Singleton access
_finops_singleton: FinOpsManager | None = None

def get_finops_manager() -> FinOpsManager:
    global _finops_singleton
    if _finops_singleton is None:
        _finops_singleton = FinOpsManager()
        # Lazy import to avoid circular dependency
        try:
            from core.metrics.cost_ledger import register_cost_subscriber  # type: ignore
            def _cb(evt: dict):
                tenant = evt.get('tenant','default')
                component = evt.get('component','inference')
                cost_units = evt.get('cost_units',0.0)
                units = evt.get('units',0.0)
                _finops_singleton.ingest(tenant, component, cost_units, units, meta=evt)
            register_cost_subscriber(_cb)
        except Exception:
            pass
    return _finops_singleton
