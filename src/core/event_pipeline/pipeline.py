from __future__ import annotations

import logging
import time
from typing import Any, Deque, Dict, List

from core.graph.hopgraph_lite import get_graph
from core.quality.factor_entropy import observe_factors

from .allowlist import AllowlistManager
from .circuit_breaker import MemoryCircuitBreaker
from .metrics import PipelineMetrics
from .stages import STAGE_DEFINITIONS, StageContext, StageResult
from .types import PipelineResult, StageTiming
from .utils import cfg_get


class EventPipeline:
    """Coordinates event processing across modular stages."""

    _NON_TERMINAL_BREAK_STAGES = {'baseline'}
    _METRIC_COMPAT_ATTRS = (
        'stage_latency',
        'heavy_stage_latency',
        'pipeline_confidence',
        'pipeline_events',
        'stage_exec_counter',
        'stage_skip_counter',
        'allowlist_hits',
        'groundtruth_outcomes',
        'confidence_bucket_counter',
        'parent_child_counter',
        'beacon_counter',
    )

    def __init__(self, config: Any, *, metrics: PipelineMetrics | None = None) -> None:
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.metrics = metrics or PipelineMetrics()
        self.allowlist = AllowlistManager(config, self.metrics)
        self.circuit_breaker = MemoryCircuitBreaker(config, self.metrics, self.logger)
        self._sync_metric_compat_attrs()
        self._lane_registry = None

        blend_cfg = cfg_get(cfg_get(config, 'pipeline', {}), 'blending', {})
        self.baseline_weight = float(cfg_get(blend_cfg, 'baseline_weight', 1.0) or 1.0)
        self.regex_weight = float(cfg_get(blend_cfg, 'regex_weight', 1.0) or 1.0)
        self.max_confidence = float(cfg_get(blend_cfg, 'cap', 1.0) or 1.0)
        self.blending_mode = str(cfg_get(blend_cfg, 'mode', 'add') or 'add').lower()
        self.heavy_skip_threshold = float(cfg_get(cfg_get(config, 'pipeline', {}), 'heavy_skip_confidence', 0.8) or 0.8)
        self._egress_history: Dict[str, Deque[float]] = {}

    async def initialize(self) -> None:
        self.logger.info('Event pipeline initialized')

    async def shutdown(self) -> None:
        self.logger.info('Event pipeline shutdown')

    async def process_event(self, event: Dict[str, Any]) -> PipelineResult:
        start = time.perf_counter()
        event_id = event.get('id', 'unknown')

        correlation_disabled = self.circuit_breaker.evaluate()

        try:
            get_graph().observe(event)
        except Exception:
            pass

        registry = getattr(self.config, 'module_registry', None) or getattr(self, 'module_registry', None)
        ctx = StageContext(
            registry=registry,
            config=self.config,
            logger=self.logger,
            state={
                'correlation_disabled': correlation_disabled,
                'egress_history_store': self._egress_history,
                'lane_registry': self._lane_registry,
            },
        )

        cumulative_factors: List[str] = []
        timings: List[StageTiming] = []
        skipped: List[str] = []
        confidence = 0.0
        terminal_hit = False

        for stage_def in STAGE_DEFINITIONS:
            if stage_def.heavy and confidence >= self.heavy_skip_threshold:
                skipped.append(stage_def.name)
                self.metrics.record_stage_skip(stage_def.name, 'confidence_gate')
                continue

            ctx.state['factors'] = list(cumulative_factors)
            result = await stage_def.runner(event, ctx)
            if not isinstance(result, StageResult):
                self._lane_registry = ctx.state.get('lane_registry', self._lane_registry)
                continue

            stage_factors = list(result.factors or [])
            metadata = result.metadata or {}
            if 'replace_factors' in metadata:
                replacement = list(metadata['replace_factors'])
                cumulative_factors = replacement
                ctx.state['factors'] = list(cumulative_factors)
                stage_factors = []
            elif stage_factors:
                cumulative_factors.extend(stage_factors)
                ctx.state['factors'] = list(cumulative_factors)

            confidence = self._blend(confidence, float(result.confidence_delta or 0.0), stage_def.name)

            if stage_def.name == 'parent_child' and any(f == 'suspicious_parent_child_pair' for f in stage_factors):
                self.metrics.increment_parent_child()
            if stage_def.name == 'beacon' and stage_factors:
                self.metrics.increment_beacon()

            self.metrics.record_stage(stage_def.name, result.duration_ms, confidence, heavy=stage_def.heavy)
            self.metrics.record_stage_execution(stage_def.name)

            self._lane_registry = ctx.state.get('lane_registry', self._lane_registry)

            timings.append(StageTiming(
                name=stage_def.name,
                duration_ms=result.duration_ms,
                confidence_after=confidence,
                factors_added=stage_factors,
            ))

            if result.terminal and stage_def.name not in self._NON_TERMINAL_BREAK_STAGES:
                terminal_hit = True
                break

        confidence, allowlist_factors = self.allowlist.apply(event, cumulative_factors, confidence)
        if allowlist_factors:
            cumulative_factors.extend(allowlist_factors)

        observe_factors(cumulative_factors)

        total_time = (time.perf_counter() - start) * 1000
        self.metrics.increment_pipeline_events(terminal_hit)
        self.metrics.record_confidence_bucket(confidence)

        timings_factored = ','.join(f"{t.name}:{t.duration_ms:.2f}ms" for t in timings)
        if timings_factored:
            cumulative_factors.append(f'timings:{timings_factored}')

        result = PipelineResult(
            event_id=event_id,
            stage='terminal' if terminal_hit else 'complete',
            confidence=confidence,
            factors=cumulative_factors,
            processing_time=total_time,
        )
        result.stage_timings = [t.__dict__ for t in timings]
        result.skipped_stages = skipped
        return result

    def _sync_metric_compat_attrs(self) -> None:
        metrics_cls = self.metrics.__class__
        for attr in self._METRIC_COMPAT_ATTRS:
            value = getattr(metrics_cls, attr, None)
            if value is not None:
                setattr(self.__class__, attr, value)

    def _blend(self, current: float, incoming: float, stage_name: str) -> float:
        if not incoming:
            return max(0.0, min(self.max_confidence, current))
        try:
            if self.blending_mode == 'max':
                return min(self.max_confidence, max(current, incoming))
            if self.blending_mode == 'weighted_max':
                candidate = current + incoming * 0.5
                return min(self.max_confidence, max(current, candidate))
            # default additive
            weight = self.baseline_weight if stage_name == 'baseline' else self.regex_weight
            return min(self.max_confidence, current + incoming * weight)
        except Exception:
            return min(self.max_confidence, max(current, current + incoming))
