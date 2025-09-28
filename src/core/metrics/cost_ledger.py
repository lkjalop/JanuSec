"""Cost Ledger & Inference Path Instrumentation

Lightweight module to track cost & usage metrics for AI/model inference paths.
This is an in-memory implementation; future iterations may persist to a DB.
"""
from __future__ import annotations
import time
from typing import Dict, Any
from dataclasses import dataclass, asdict
import threading

try:
    from prometheus_client import Counter, Histogram
except Exception:  # pragma: no cover
    Counter = None  # type: ignore
    Histogram = None  # type: ignore

_lock = threading.Lock()

@dataclass
class InferenceRecord:
    tier: str
    path: str  # name or model id
    latency_ms: float
    tokens: int
    cached: bool
    success: bool
    timestamp: float

_subscribers: list = []  # callables: fn(event_dict)

def register_cost_subscriber(cb):  # simple subscription (FinOps, etc.)
    if cb not in _subscribers:
        _subscribers.append(cb)

class CostLedger:
    def __init__(self):
        self.records: list[InferenceRecord] = []
        if Counter and Histogram and not hasattr(self.__class__, '_init'):
            try:
                self.__class__.inference_calls = Counter('inference_calls_total','Inference calls', ['tier','path','cached','success'])
                self.__class__.inference_latency = Histogram('inference_latency_ms','Inference latency (ms)', ['tier','path'])
                self.__class__.inference_tokens = Counter('inference_tokens_total','Tokens consumed', ['tier','path'])
                self.__class__._init = True
            except Exception:
                pass

    def record(self, tier: str, path: str, start: float, tokens: int = 0, cached: bool = False, success: bool = True):
        latency_ms = (time.perf_counter() - start) * 1000.0
        rec = InferenceRecord(tier=tier, path=path, latency_ms=latency_ms, tokens=tokens, cached=cached, success=success, timestamp=time.time())
        with _lock:
            self.records.append(rec)
            # truncate to last 10k
            if len(self.records) > 10000:
                self.records = self.records[-5000:]
        if hasattr(self.__class__, 'inference_calls'):
            try:
                self.__class__.inference_calls.labels(tier=tier, path=path, cached=str(cached), success=str(success)).inc()
                self.__class__.inference_latency.labels(tier=tier, path=path).observe(latency_ms)
                if tokens:
                    self.__class__.inference_tokens.labels(tier=tier, path=path).inc(tokens)
            except Exception:
                pass
        # Notify subscribers (FinOps). Basic cost modeling: treat tokens or call as unit cost basis
        evt = {
            'timestamp': rec.timestamp,
            'tenant': rec.meta.get('tenant','default') if isinstance(rec := rec, InferenceRecord) else 'default',
            'component': 'inference',
            'units': rec.tokens or 1,
            'cost_units': (rec.tokens or 1) * 0.001,  # placeholder conversion
            'tier': tier,
            'path': path,
            'cached': cached,
            'success': success
        }
        for cb in list(_subscribers):
            try:
                cb(evt)
            except Exception:
                continue

    def summary(self) -> Dict[str, Any]:
        agg: Dict[str, Dict[str, Any]] = {}
        with _lock:
            for r in self.records:
                key = (r.tier, r.path)
                if key not in agg:
                    agg[key] = { 'calls': 0, 'latency_sum': 0.0, 'tokens': 0, 'cached_hits': 0, 'success': 0 }
                a = agg[key]
                a['calls'] += 1
                a['latency_sum'] += r.latency_ms
                a['tokens'] += r.tokens
                if r.cached:
                    a['cached_hits'] += 1
                if r.success:
                    a['success'] += 1
        # compute derived stats
        report = []
        for (tier, path), a in agg.items():
            avg_latency = a['latency_sum']/a['calls'] if a['calls'] else 0.0
            cache_rate = a['cached_hits']/a['calls'] if a['calls'] else 0.0
            success_rate = a['success']/a['calls'] if a['calls'] else 0.0
            report.append({
                'tier': tier,
                'path': path,
                'calls': a['calls'],
                'avg_latency_ms': round(avg_latency,2),
                'cache_hit_rate': round(cache_rate,3),
                'success_rate': round(success_rate,3),
                'tokens': a['tokens']
            })
        return { 'inference_summary': report }

# Singleton accessor
_cost_ledger: CostLedger | None = None

def get_cost_ledger() -> CostLedger:
    global _cost_ledger
    if _cost_ledger is None:
        _cost_ledger = CostLedger()
    return _cost_ledger
