"""Lane Registry - manages hunt lanes execution in advisory mode.

Initial version: lanes only add advisory factors (no direct confidence impact) until
metrics prove value. Toggle via config: pipeline.hunt_lanes.enabled
Per-lane enable flags: pipeline.hunt_lanes.lanes.<lane_name>=true|false
"""
from __future__ import annotations
from typing import Dict, Any, List, Protocol, Callable, Awaitable
import os
import logging

try:
    from prometheus_client import Histogram, Counter, Gauge
except Exception:  # pragma: no cover
    Histogram = None  # type: ignore
    Counter = None    # type: ignore
    Gauge = None      # type: ignore

logger = logging.getLogger(__name__)

class Lane(Protocol):  # interface for type checkers
    name: str
    async def run(self, envelope, context) -> None: ...

class LaneRegistry:
    def __init__(self, config):
        self.config = config
        self.lanes: Dict[str, Lane] = {}
        self._init_metrics()

    def _init_metrics(self):
        if getattr(self.__class__, '_metrics_init', False):
            return
        try:
            self.__class__.lane_latency = Histogram('hunt_lane_latency_ms', 'Latency per hunt lane (ms)', ['lane']) if Histogram else None
            self.__class__.lane_events = Counter('hunt_lane_events_total','Total lane executions resulting in factors', ['lane']) if Counter else None
            self.__class__.lane_batch_latency = Histogram('hunt_lanes_batch_latency_ms','Total latency for all lanes per event (ms)', ['mode']) if Histogram else None
            self.__class__.lane_parallel_enabled = Gauge('hunt_lanes_parallel_enabled','Parallel lane execution enabled (1/0)') if Gauge else None
            self.__class__._metrics_init = True
        except Exception:
            pass

    def register(self, lane: Lane):
        self.lanes[lane.name] = lane

    def enabled(self) -> bool:
        try:
            return bool(self.config.get('pipeline', {}).get('hunt_lanes', {}).get('enabled', True))
        except Exception:
            return True

    def lane_enabled(self, name: str) -> bool:
        try:
            hl = self.config.get('pipeline', {}).get('hunt_lanes', {})
            lanes_cfg = hl.get('lanes', {})
            if name in lanes_cfg:
                return bool(lanes_cfg[name])
            return True
        except Exception:
            return True

    async def run_lanes(self, envelope):
        if not self.enabled():
            return envelope
        parallel = os.getenv('HUNT_LANES_PARALLEL','false').lower() in ('1','true','yes')
        if getattr(self.__class__, 'lane_parallel_enabled', None):
            try: self.__class__.lane_parallel_enabled.set(1 if parallel else 0)
            except Exception: pass
        import time, asyncio
        start = time.perf_counter()
        if not parallel:
            for name, lane in self.lanes.items():
                if not self.lane_enabled(name):
                    continue
                await self._execute_lane(name, lane, envelope)
            mode = 'sequential'
        else:
            tasks = []
            for name, lane in self.lanes.items():
                if not self.lane_enabled(name):
                    continue
                tasks.append(self._execute_lane(name, lane, envelope))
            await asyncio.gather(*tasks, return_exceptions=True)
            mode = 'parallel'
        total_ms = (time.perf_counter() - start) * 1000.0
        if getattr(self.__class__, 'lane_batch_latency', None):
            try: self.__class__.lane_batch_latency.labels(mode=mode).observe(total_ms)
            except Exception: pass
        return envelope

    async def _execute_lane(self, name: str, lane: Lane, envelope):
        # Direct import instead of dynamic __import__ for clarity & tooling friendliness
        from .evidence_envelope import LaneContext  # local import to avoid circulars at module import time
        ctx = LaneContext()
        try:
            await lane.run(envelope, ctx)
            elapsed = ctx.elapsed_ms()
            # Sanitize emissions: ensure lane_ prefix (defense-in-depth)
            if getattr(envelope, 'emissions', None) and envelope.emissions and envelope.emissions[-1].lane == name:
                em = envelope.emissions[-1]
                fixed = []
                changed = False
                for f in em.factors:
                    if not f.startswith('lane_'):
                        fixed.append(f'lane_{name}:{f}')
                        changed = True
                    else:
                        fixed.append(f)
                if changed:
                    em.factors = fixed
                    if hasattr(envelope, 'lane_factors'):
                        envelope.lane_factors = [ff if ff.startswith('lane_') else f'lane_{name}:{ff}' for ff in envelope.lane_factors]
            if hasattr(envelope, 'emissions') and envelope.emissions and envelope.emissions[-1].lane == name:
                envelope.emissions[-1].latency_ms = elapsed
            if getattr(self.__class__, 'lane_latency', None):
                self.__class__.lane_latency.labels(lane=name).observe(elapsed)
            if getattr(self.__class__, 'lane_events', None) and envelope.emissions and envelope.emissions[-1].lane == name:
                self.__class__.lane_events.labels(lane=name).inc()
        except Exception as e:  # broad catch for lane isolation; log stack for debugging
            logger.exception(f"Lane {name} failed")
