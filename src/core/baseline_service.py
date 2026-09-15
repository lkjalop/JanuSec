"""Per-Entity Baseline Service

Maintains incremental EWMA + Welford variance per (entity_type, entity_id, metric).
Provides z-score computation and anomaly factor signaling.
"""
from __future__ import annotations

import os
import time
import math
import asyncio
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, Iterable, Any

try:  # pragma: no cover
    from prometheus_client import Counter, Gauge  # type: ignore
except Exception:  # pragma: no cover
    class _MetricShim:
        """Minimal shim when prometheus_client is unavailable."""

        def __init__(self,*_a,**_k) -> None:
            pass
        def labels(self,*_a,**_k):
            return self
        def inc(self,*_a,**_k) -> None:
            return None
        def set(self,*_a,**_k) -> None:
            return None

    Counter = Gauge = _MetricShim  # type: ignore

_ALPHA_DEFAULT = float(os.getenv('BASELINE_ALPHA','0.2') or 0.2)

def _alpha_for_metric(metric: str) -> float:
    env_key = f'BASELINE_ALPHA_{metric}'.upper().replace('-','_')
    try:
        val = os.getenv(env_key)
        if val is not None:
            f = float(val)
            if f > 0:
                return f
    except Exception:
        pass
    return _ALPHA_DEFAULT
_ANOMALY_Z = float(os.getenv('BASELINE_ANOMALY_Z','3.0') or 3.0)
_TTL_SECONDS = int(os.getenv('BASELINE_TTL_SECONDS','86400') or 86400)
_MIN_STD = float(os.getenv('BASELINE_MIN_STD','1e-6') or 1e-6)

baseline_entities_total = Counter('baseline_entities_total','Distinct baseline entities tracked',['entity_type','metric'])
baseline_updates_total = Counter('baseline_updates_total','Baseline updates',['entity_type','metric'])
baseline_anomalies_total = Counter('baseline_anomalies_total','Baseline anomalies',['entity_type','metric'])

@dataclass
class BaselineRecord:
    entity_type: str
    entity_id: str
    metric: str
    count: int = 0
    mean: float = 0.0          # EWMA mean
    welford_mean: float = 0.0  # For variance
    m2: float = 0.0            # Welford accumulated sum of squares
    last_value: float = 0.0
    last_ts: float = 0.0
    alpha: float = _ALPHA_DEFAULT

    def update(self, value: float, ts: float | None = None) -> None:
        if not math.isfinite(value):
            return
        t = ts or time.time()
        self.count += 1
        # EWMA mean
        if self.count == 1:
            self.mean = value
            self.welford_mean = value
            self.m2 = 0.0
        else:
            self.mean = self.mean + self.alpha * (value - self.mean)
            # Welford for unbiased variance (not EWMA)
            delta = value - self.welford_mean
            self.welford_mean += delta / self.count
            delta2 = value - self.welford_mean
            self.m2 += delta * delta2
        self.last_value = value
        self.last_ts = t

    @property
    def variance(self) -> float:
        if self.count < 2:
            return _MIN_STD ** 2
        return max(_MIN_STD**2, self.m2 / (self.count - 1))

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, current: float) -> float:
        if not math.isfinite(current):
            return 0.0
        return (current - self.mean) / max(self.stddev, _MIN_STD)


class BaselineService:
    def __init__(self):
        self._store: Dict[Tuple[str,str,str], BaselineRecord] = {}
        self._lock = asyncio.Lock()
        self._persist_path = os.getenv('BASELINE_PERSIST_PATH')
        self._persist_interval = int(os.getenv('BASELINE_PERSIST_INTERVAL_SECONDS','0') or 0)
        self._last_persist = 0.0
        # Attempt load
        if self._persist_path and os.path.isfile(self._persist_path):
            try:
                import json
                with open(self._persist_path,'r',encoding='utf-8') as fh:
                    data = json.load(fh)
                now = time.time()
                for rec in data.get('records', []):
                    br = BaselineRecord(**{k: rec[k] for k in ('entity_type','entity_id','metric','count','mean','welford_mean','m2','last_value','last_ts','alpha')})
                    # Respect TTL upon load
                    if _TTL_SECONDS > 0 and (now - br.last_ts) > _TTL_SECONDS:
                        continue
                    self._store[(br.entity_type, br.entity_id, br.metric)] = br
            except Exception:
                pass

    async def update(self, entity_type: str, entity_id: str, metric: str, value: float, *, alpha: float | None = None) -> BaselineRecord:
        key = (entity_type, entity_id, metric)
        async with self._lock:
            # Evict stale entries first so we don't accidentally remove a newly
            # created record that still has default timestamps (last_ts == 0.0).
            self._evict_stale_locked()
            rec = self._store.get(key)
            if rec is None:
                rec = BaselineRecord(entity_type, entity_id, metric, alpha=alpha or _alpha_for_metric(metric))
                self._store[key] = rec
                try:
                    baseline_entities_total.labels(entity_type=entity_type, metric=metric).inc()
                except Exception:
                    pass
            if alpha is not None and alpha > 0:
                rec.alpha = alpha
            rec.update(value)
            try: baseline_updates_total.labels(entity_type=entity_type, metric=metric).inc()
            except Exception: pass
            self._maybe_persist_locked()
            return rec

    async def get(self, entity_type: str, entity_id: str, metric: str) -> Optional[BaselineRecord]:
        async with self._lock:
            self._evict_stale_locked()
            self._maybe_persist_locked()
            return self._store.get((entity_type, entity_id, metric))

    async def get_z(self, entity_type: str, entity_id: str, metric: str, current_value: float | None = None) -> dict[str, Any]:
        rec = await self.get(entity_type, entity_id, metric)
        if rec is None:
            if current_value is None:
                return {'z': 0.0, 'mean': 0.0, 'stddev': _MIN_STD, 'samples': 0, 'anomaly': False}
            # Implicitly create baseline on first query with value
            rec = await self.update(entity_type, entity_id, metric, float(current_value))
            return {'z': 0.0, 'mean': rec.mean, 'stddev': rec.stddev, 'samples': rec.count, 'anomaly': False}
        value = rec.last_value if current_value is None else float(current_value)
        z = rec.z_score(value)
        anomaly = abs(z) >= _ANOMALY_Z and rec.count > 5
        if anomaly:
            try: baseline_anomalies_total.labels(entity_type=entity_type, metric=metric).inc()
            except Exception: pass
        return {'z': z, 'mean': rec.mean, 'stddev': rec.stddev, 'samples': rec.count, 'anomaly': anomaly}

    async def batch_get_z(self, items: Iterable[dict]) -> list[dict[str, Any]]:
        results = []
        for it in items:
            res = await self.get_z(it['entity_type'], it['entity_id'], it['metric'], it.get('current_value'))
            results.append({**it, **res})
        return results

    def _evict_stale_locked(self) -> None:
        if _TTL_SECONDS <= 0:
            return
        now = time.time()
        # Only consider records with a positive last_ts. Some records may have
        # last_ts == 0.0 (default) during creation/update flows; evicting those
        # can remove entries prematurely in concurrent/test scenarios. Ensure
        # we only evict entries that have a real timestamp and are older than TTL.
        stale = [k for k,v in self._store.items() if (v.last_ts > 0 and (now - v.last_ts) > _TTL_SECONDS)]
        for k in stale:
            self._store.pop(k, None)

    async def size(self) -> int:
        async with self._lock:
            self._evict_stale_locked()
            self._maybe_persist_locked()
            return len(self._store)

    async def delete(self, entity_type: str, entity_id: str, metric: str) -> bool:
        key = (entity_type, entity_id, metric)
        async with self._lock:
            existed = key in self._store
            self._store.pop(key, None)
            self._maybe_persist_locked()
            return existed

    def _maybe_persist_locked(self) -> None:
        if not self._persist_path or self._persist_interval <= 0:
            return
        now = time.time()
        if (now - self._last_persist) < self._persist_interval:
            return
        self._last_persist = now
        try:
            import json, tempfile, os as _os
            serial = {'records': [
                {
                    'entity_type': r.entity_type,
                    'entity_id': r.entity_id,
                    'metric': r.metric,
                    'count': r.count,
                    'mean': r.mean,
                    'welford_mean': r.welford_mean,
                    'm2': r.m2,
                    'last_value': r.last_value,
                    'last_ts': r.last_ts,
                    'alpha': r.alpha
                } for r in self._store.values()
            ], 'version':1}
            tmp_fd, tmp_path = tempfile.mkstemp(prefix='baseline_', suffix='.json')
            with open(tmp_fd,'w',encoding='utf-8') as fh:
                json.dump(serial, fh)
            _os.replace(tmp_path, self._persist_path)
        except Exception:
            pass


BASELINES = BaselineService()

__all__ = ['BASELINES','BaselineService']
