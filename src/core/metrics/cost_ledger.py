"""Cost Ledger & Inference Path Instrumentation

Lightweight module to track cost & usage metrics for AI/model inference paths.
This is an in-memory implementation; future iterations may persist to a DB.
"""
from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Dict

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
        # lightweight budget store for tenants and named entries
        self._budgets: dict[str, float] = {}
        self._snapshot_path = Path('artifacts/metrics/cost_ledger.jsonl')
        if Counter and Histogram and not hasattr(self.__class__, '_init'):
            try:
                self.__class__.inference_calls = Counter('inference_calls_total','Inference calls', ['tier','path','cached','success'])
                self.__class__.inference_latency = Histogram('inference_latency_ms','Inference latency (ms)', ['tier','path'])
                self.__class__.inference_tokens = Counter('inference_tokens_total','Tokens consumed', ['tier','path'])
                self.__class__._init = True
            except Exception:
                pass

    def record(self, tier: str, path: str, start: float, tokens: int = 0, cached: bool = False, success: bool = True, tenant: str | None = None):
        latency_ms = (time.perf_counter() - start) * 1000.0
        rec = InferenceRecord(tier=tier, path=path, latency_ms=latency_ms, tokens=tokens, cached=cached, success=success, timestamp=time.time())
        with _lock:
            self.records.append(rec)
            # truncate to last 10k
            if len(self.records) > 10000:
                self.records = self.records[-5000:]
            # append snapshot best-effort
            try:
                self._snapshot_path.parent.mkdir(parents=True, exist_ok=True)
                with self._snapshot_path.open('a', encoding='utf-8') as fh:
                    fh.write(json.dumps(asdict(rec)) + '\n')
            except Exception:
                pass
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
            'tenant': tenant or 'default',
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

    def summary(self) -> dict[str, Any]:
        agg: dict[str, dict[str, Any]] = {}
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

    def token_bins(self, edges: list[int] | None = None) -> dict[str, Any]:
        """Compute token usage histogram bins from recorded inference calls.

        Edges define upper bounds for bins (e.g., [1000, 5000, 20000]).
        Returns a dict with 'edges', 'bins' (list of {range, count}), and 'total'.
        """
        try:
            if edges is None:
                import os as _os
                raw = _os.getenv('TOKEN_BIN_EDGES', '')
                parts = [p.strip() for p in raw.split(',') if p.strip()]
                edges = []
                for p in parts:
                    try:
                        edges.append(int(p))
                    except Exception:
                        continue
                if not edges:
                    edges = [1000, 5000, 20000]
            edges = sorted([int(e) for e in edges if isinstance(e, (int, float))])
        except Exception:
            edges = [1000, 5000, 20000]
        # Prepare bins
        bounds: list[tuple[int, int | None]] = []
        prev = 0
        for e in edges:
            bounds.append((prev, int(e)))
            prev = int(e)
        bounds.append((prev, None))  # final open-ended bin
        labels: list[str] = []
        for lo, hi in bounds:
            if hi is None:
                labels.append(f">= {lo}")
            else:
                labels.append(f"{lo}-{hi-1}")
        counts = [0 for _ in bounds]
        total = 0
        with _lock:
            for r in self.records:
                t = int(r.tokens or 0)
                total += 1
                # find bin
                placed = False
                for idx, (lo, hi) in enumerate(bounds):
                    if hi is None:
                        if t >= lo:
                            counts[idx] += 1
                            placed = True
                            break
                    else:
                        if lo <= t < hi:
                            counts[idx] += 1
                            placed = True
                            break
                if not placed:
                    # if negative or unexpected, count in first bin
                    counts[0] += 1
        return {
            'edges': edges,
            'bins': [{'range': labels[i], 'count': counts[i]} for i in range(len(bounds))],
            'total': total
        }

    def load_snapshot(self, max_rows: int = 20000) -> int:
        """Load prior records from snapshot file for restart resilience."""
        try:
            p = self._snapshot_path
            if not p.exists():
                return 0
            lines = p.read_text(encoding='utf-8').splitlines()
            count = 0
            with _lock:
                for line in lines[-max_rows:]:
                    try:
                        j = json.loads(line)
                        rec = InferenceRecord(
                            tier=j.get('tier','unknown'), path=j.get('path','unknown'), latency_ms=float(j.get('latency_ms') or 0.0),
                            tokens=int(j.get('tokens') or 0), cached=bool(j.get('cached')), success=bool(j.get('success')), timestamp=float(j.get('timestamp') or time.time())
                        )
                        self.records.append(rec)
                        count += 1
                    except Exception:
                        continue
            return count
        except Exception:
            return 0

# Singleton accessor
_cost_ledger: CostLedger | None = None

def get_cost_ledger() -> CostLedger:
    global _cost_ledger
    if _cost_ledger is None:
        _cost_ledger = CostLedger()
    return _cost_ledger

    # Backwards-compatible cost helpers for simple key/value budgets
    def set_budget(self, key: str, value: float):
        try:
            with _lock:
                self._budgets[key] = float(value)
        except Exception:
            pass

    def get_budget(self, key: str) -> float:
        try:
            with _lock:
                return float(self._budgets.get(key, 0.0))
        except Exception:
            return 0.0

    def add_cost(self, key: str, amount: float):
        try:
            with _lock:
                self._budgets[key] = self._budgets.get(key, 0.0) + float(amount)
        except Exception:
            pass

    def get_cost(self, key: str) -> float:
        return self.get_budget(key)

    @classmethod
    def get_instance(cls) -> 'CostLedger':
        return get_cost_ledger()
