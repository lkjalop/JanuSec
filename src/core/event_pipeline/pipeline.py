from __future__ import annotations

import logging
import time
from collections import deque
import os
from datetime import datetime
from typing import Any, Deque, Dict, List

from core.graph.hopgraph_lite import get_graph
from core.quality.factor_entropy import observe_factors

try:
    from src.core.correlation.factor_synthesis import Factor, FactorCategory  # type: ignore
    from src.core.correlation.factor_synthesis_runtime import (  # type: ignore
        get_factor_synthesis_engine,
        factor_category_for_name,
    )
except Exception:  # pragma: no cover
    Factor = None  # type: ignore
    FactorCategory = None  # type: ignore
    get_factor_synthesis_engine = None  # type: ignore
    factor_category_for_name = None  # type: ignore

from .allowlist import AllowlistManager
from .circuit_breaker import MemoryCircuitBreaker
from .metrics import PipelineMetrics
from .scoring import adjust_confidence
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
        self._egress_history: dict[str, deque[float]] = {}

    async def initialize(self) -> None:
        self.logger.info('Event pipeline initialized')

    async def shutdown(self) -> None:
        self.logger.info('Event pipeline shutdown')

    async def process_event(self, event: dict[str, Any]) -> PipelineResult:
        start = time.perf_counter()
        event_id = event.get('id', 'unknown')

        correlation_disabled = self.circuit_breaker.evaluate()
        breaker_state = self.circuit_breaker.snapshot()

        # Per-tenant heavy stage gating overrides
        tenant_id = str(event.get('tenant_id') or os.getenv('DEFAULT_TENANT', 'default'))
        heavy_skip_threshold_evt = self.heavy_skip_threshold
        try:
            from src.core.config.tenant_overrides import get_overrides  # type: ignore
            _ov = get_overrides(tenant_id) or {}
            if isinstance(_ov.get('heavy_skip_confidence'), (int, float)):
                heavy_skip_threshold_evt = float(_ov.get('heavy_skip_confidence'))
        except Exception:
            pass

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
                'enrichment_cache': {},
                'breaker_state': breaker_state,
            },
        )

        cumulative_factors: list[str] = []
        timings: list[StageTiming] = []
        skipped: list[str] = []
        confidence = 0.0
        terminal_hit = False

        for stage_def in STAGE_DEFINITIONS:
            # Optional skip-by-confidence gate (tenant-aware threshold)
            if stage_def.heavy and confidence >= heavy_skip_threshold_evt:
                skipped.append(stage_def.name)
                self.metrics.record_stage_skip(stage_def.name, 'confidence_gate')
                continue

            # Optional under-load selective skip for heavy stages (per-tenant flags)
            if correlation_disabled:
                try:
                    _ov = _ov if '_ov' in locals() else {}
                    if stage_def.name == 'beacon' and bool(_ov.get('skip_beacon_under_load')):
                        skipped.append(stage_def.name)
                        self.metrics.record_stage_skip(stage_def.name, 'under_load')
                        continue
                    if stage_def.name == 'egress' and bool(_ov.get('skip_egress_under_load')):
                        skipped.append(stage_def.name)
                        self.metrics.record_stage_skip(stage_def.name, 'under_load')
                        continue
                    if stage_def.name == 'domain_novelty' and bool(_ov.get('skip_domain_novelty_under_load')):
                        skipped.append(stage_def.name)
                        self.metrics.record_stage_skip(stage_def.name, 'under_load')
                        continue
                except Exception:
                    pass

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

        confidence, adjustment_meta = adjust_confidence(event, cumulative_factors, confidence)
        extra_factors = adjustment_meta.get('extra_factors') or []
        if extra_factors:
            cumulative_factors.extend(extra_factors)

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
        ctx.state['breaker_state'] = self.circuit_breaker.snapshot()
        metadata = dict(adjustment_meta or {})
        enrichment_cache = ctx.state.get('enrichment_cache')
        if enrichment_cache:
            metadata['enrichment'] = enrichment_cache
        breaker_meta = ctx.state.get('breaker_state')
        if breaker_meta:
            metadata['breaker_state'] = breaker_meta
        result.metadata = metadata
        synthesis = self._compute_factor_synthesis(event, cumulative_factors)
        if synthesis:
            insight = {
                'type': 'factor_synthesis',
                'confidence': synthesis.confidence,
                'final_score': synthesis.final_score,
                'synergies': synthesis.synergies_detected,
                'factor_synthesis': {
                    'final_score': synthesis.final_score,
                    'confidence': synthesis.confidence,
                    'contributing_factors': synthesis.contributing_factors,
                    'synergies': synthesis.synergies_detected,
                    'context_multiplier': synthesis.context_multiplier,
                    'decay_applied': synthesis.decay_applied,
                    'explanation': synthesis.explanation,
                },
            }
            result.metadata.setdefault('correlation_insights', []).append(insight)
            result.metadata['factor_synthesis'] = insight['factor_synthesis']
            result.metadata['factor_synthesis_insight'] = insight
            result.metadata['baseline_confidence'] = result.confidence
            result.confidence = float(synthesis.confidence)
        return result

    def _sync_metric_compat_attrs(self) -> None:
        metrics_cls = self.metrics.__class__
        for attr in self._METRIC_COMPAT_ATTRS:
            value = getattr(metrics_cls, attr, None)
            if value is not None:
                setattr(self.__class__, attr, value)

    def _build_synthesis_context(self, event: dict[str, Any]) -> dict[str, Any]:
        ctx: dict[str, Any] = {}
        if not isinstance(event, dict):
            return ctx
        for key in ('tenant_id', 'severity', 'domain', 'source', 'ingest_source', 'role'):
            val = event.get(key)
            if val:
                ctx[key] = val
        return ctx

    def _compute_factor_synthesis(self, event: dict[str, Any], factors: list[str]):
        if not (Factor and FactorCategory and get_factor_synthesis_engine and factor_category_for_name):
            return None
        engine = get_factor_synthesis_engine()
        if engine is None:
            return None
        now_dt = datetime.utcnow()
        uniq = []
        seen: set[str] = set()
        for name in factors:
            if name in seen:
                continue
            seen.add(name)
            try:
                category = factor_category_for_name(name)
            except Exception:
                category = FactorCategory.META  # type: ignore[attr-defined]
            try:
                uniq.append(
                    Factor(
                        name=name,
                        category=category,
                        timestamp=now_dt,
                        base_weight=0.5,
                        metadata={},
                    )
                )
            except Exception:
                continue
        if not uniq:
            return None
        try:
            return engine.synthesize(uniq, context=self._build_synthesis_context(event))
        except Exception:
            return None

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
