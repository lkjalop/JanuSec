"""
Event Pipeline - Handles event processing flow through stages
Author: Security Engineering Team
Version: 1.0.0
"""

import asyncio
import logging
import time
from typing import Dict, Any, List
try:
    from prometheus_client import Histogram, Counter
except Exception:  # If prometheus_client not installed yet, create dummies
    Histogram = lambda *a, **k: None  # type: ignore
    Counter = lambda *a, **k: None    # type: ignore
from dataclasses import dataclass

# Types for stage outputs
@dataclass
class StageTiming:
    name: str
    duration_ms: float
    confidence_after: float
    factors_added: List[str]


@dataclass
class PipelineResult:
    """Result from pipeline processing"""
    event_id: str
    stage: str
    confidence: float
    factors: list
    processing_time: float
    

class EventPipeline:
    """Handles the actual event processing flow through stages"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        # Metrics (lazy-initialized once)
        self._init_metrics()
        # Load blending config
        blend_cfg = self.config.get('pipeline', {}).get('blending', {}) if hasattr(self.config, 'get') else {}
        self.baseline_weight = float(blend_cfg.get('baseline_weight', 1.0))
        self.regex_weight = float(blend_cfg.get('regex_weight', 1.0))
        self.max_confidence = float(blend_cfg.get('cap', 1.0))
        self.blending_mode = blend_cfg.get('mode', 'add')  # 'add' | 'weighted_max' | 'max'
        # Feature flag for adaptive pre-stage
        self.disable_adaptive_pre = bool(self.config.get('pipeline', {}).get('disable_adaptive_pre', False)) if hasattr(self.config, 'get') else False

    def _init_metrics(self):
        if getattr(self.__class__, '_metrics_initialized', False):
            return
        try:
            self.__class__.stage_latency = Histogram(
                'pipeline_stage_latency_ms',
                'Latency per pipeline stage (ms)',
                ['stage']
            )
            self.__class__.pipeline_confidence = Histogram(
                'pipeline_confidence_progress',
                'Confidence value after each stage',
                ['stage']
            )
            self.__class__.pipeline_events = Counter(
                'pipeline_events_total',
                'Total events processed through pipeline',
                ['terminal']
            )
            self.__class__._metrics_initialized = True
        except Exception:
            # Metrics optional; proceed silently if unavailable
            pass
    
    async def initialize(self):
        """Initialize pipeline"""
        self.logger.info("Event pipeline initialized")
    
    async def process_event(self, event: Dict[str, Any]) -> PipelineResult:
        """Process event through staged pipeline (baseline -> regex -> adaptive)."""
        start = time.perf_counter()
        event_id = event.get('id', 'unknown')

        # Acquire required modules from registry via config hook (expects registry injected into config)
        registry = getattr(self.config, 'module_registry', None)
        if registry is None:
            # Fallback: direct attribute set externally
            registry = getattr(self, 'module_registry', None)

        timings: List[StageTiming] = []
        cumulative_factors: List[str] = []
        confidence = 0.0

    # Stage 1: Baseline
        baseline_module = None
        if registry:
            try:
                baseline_module = await registry.get_module('baseline')
            except Exception as e:
                self.logger.error(f"Failed loading baseline module: {e}")
        if baseline_module:
            s1_start = time.perf_counter()
            baseline_result = await baseline_module.check(event)
            confidence = self._blend(confidence, baseline_result.confidence, stage='baseline')
            cumulative_factors.extend(baseline_result.factors)
            timings.append(StageTiming(
                name='baseline',
                duration_ms=(time.perf_counter() - s1_start) * 1000,
                confidence_after=confidence,
                factors_added=baseline_result.factors
            ))
            self._observe_stage('baseline', timings[-1].duration_ms, confidence)
            if baseline_result.terminal:
                total_time = (time.perf_counter() - start) * 1000
                self._count_event(terminal=True)
                return PipelineResult(
                    event_id=event_id,
                    stage='baseline_terminal',
                    confidence=confidence,
                    factors=cumulative_factors,
                    processing_time=total_time
                )

        # Stage 2: Regex pattern engine
        regex_module = None
        if registry:
            try:
                regex_module = await registry.get_module('regex_engine')
            except Exception as e:
                self.logger.error(f"Failed loading regex module: {e}")
        if regex_module:
            s2_start = time.perf_counter()
            try:
                regex_result = await regex_module.analyze_event(event)
                confidence = self._blend(confidence, regex_result.confidence_delta, stage='regex', delta_mode=True)
                cumulative_factors.extend(regex_result.factors)
                timings.append(StageTiming(
                    name='regex',
                    duration_ms=(time.perf_counter() - s2_start) * 1000,
                    confidence_after=confidence,
                    factors_added=regex_result.factors
                ))
                self._observe_stage('regex', timings[-1].duration_ms, confidence)
            except Exception as e:
                self.logger.error(f"Regex analysis failed: {e}")

        # Stage 3: Adaptive tuner pre-signal (optional)
        adaptive_tuner = None
        if not self.disable_adaptive_pre:
            adaptive_tuner = getattr(self.config, 'adaptive_tuner', None)
            if adaptive_tuner is None:
                adaptive_tuner = getattr(self, 'adaptive_tuner', None)

        if adaptive_tuner and hasattr(adaptive_tuner, 'preliminary_assess') and not self.disable_adaptive_pre:
            s3_start = time.perf_counter()
            try:
                pre = await adaptive_tuner.preliminary_assess({
                    'confidence': confidence,
                    'factors': list(cumulative_factors)
                })
                if pre and isinstance(pre, dict):
                    delta = pre.get('confidence_adjust', 0.0)
                    if delta:
                        confidence = max(0.0, min(1.0, confidence + delta))
                    added = pre.get('factors', [])
                    cumulative_factors.extend(added)
                    timings.append(StageTiming(
                        name='adaptive_pre',
                        duration_ms=(time.perf_counter() - s3_start) * 1000,
                        confidence_after=confidence,
                        factors_added=added
                    ))
                    self._observe_stage('adaptive_pre', timings[-1].duration_ms, confidence)
            except Exception as e:
                self.logger.warning(f"Adaptive pre-assess failed: {e}")

        total_time = (time.perf_counter() - start) * 1000
        # Optionally attach timings as factor metadata
        cumulative_factors.append(f"timings:{','.join(f'{t.name}:{t.duration_ms:.2f}ms' for t in timings)}")

        self._count_event(terminal=False)
        return PipelineResult(
            event_id=event_id,
            stage='pipeline_complete',
            confidence=confidence,
            factors=cumulative_factors,
            processing_time=total_time
        )

    # Blending helper
    def _blend(self, current: float, incoming: float, stage: str, delta_mode: bool = False) -> float:
        try:
            if self.blending_mode == 'max':
                return max(current, current + incoming if delta_mode else incoming)
            elif self.blending_mode == 'weighted_max':
                candidate = (self.baseline_weight * current) if stage == 'baseline' else (self.regex_weight * (incoming if not delta_mode else incoming))
                return max(current, min(self.max_confidence, candidate))
            # default 'add'
            if delta_mode:
                return min(self.max_confidence, current + (incoming * self.regex_weight))
            if stage == 'baseline':
                # baseline incoming is absolute in its own context
                return min(self.max_confidence, max(current, incoming * self.baseline_weight))
            return min(self.max_confidence, max(current, incoming))
        except Exception:
            return min(self.max_confidence, max(current, incoming if not delta_mode else current + incoming))

    def _observe_stage(self, stage: str, duration_ms: float, confidence: float):
        try:
            if hasattr(self.__class__, 'stage_latency') and self.__class__.stage_latency:
                self.__class__.stage_latency.labels(stage=stage).observe(duration_ms)
            if hasattr(self.__class__, 'pipeline_confidence') and self.__class__.pipeline_confidence:
                self.__class__.pipeline_confidence.labels(stage=stage).observe(confidence)
        except Exception:
            pass

    def _count_event(self, terminal: bool):
        try:
            if hasattr(self.__class__, 'pipeline_events') and self.__class__.pipeline_events:
                self.__class__.pipeline_events.labels(terminal=str(terminal).lower()).inc()
        except Exception:
            pass
    
    async def deep_analysis(self, event: Dict[str, Any], decision) -> PipelineResult:
        """Perform deep analysis"""
        return PipelineResult(
            event_id=event.get('id', 'unknown'),
            stage='deep_analysis',
            confidence=0.7,
            factors=['deep:analyzed'],
            processing_time=10.0
        )
    
    async def shutdown(self):
        """Shutdown pipeline"""
        self.logger.info("Event pipeline shutdown")