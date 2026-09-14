from __future__ import annotations

import contextlib
from typing import Optional


class PipelineMetrics:
    _initialized = False
    stage_latency = None
    heavy_stage_latency = None
    pipeline_confidence = None
    pipeline_events = None
    stage_exec_counter = None
    stage_skip_counter = None
    allowlist_hits = None
    groundtruth_outcomes = None
    confidence_bucket_counter = None
    parent_child_counter = None
    beacon_counter = None
    rss_gauge = None
    mem_trip_total = None
    breaker_state_gauge = None
    breaker_fallback_counter = None

    def __init__(self) -> None:
        self._ensure_core_metrics()

    @classmethod
    def _ensure_core_metrics(cls) -> None:
        if cls._initialized:
            return
        try:
            from prometheus_client import Counter, Gauge, Histogram  # type: ignore
        except Exception:  # pragma: no cover - metrics optional
            cls._initialized = True
            return
        try:
            cls.stage_latency = Histogram(
                'pipeline_stage_latency_ms',
                'Latency per pipeline stage (ms)',
                ['stage']
            )
            cls.heavy_stage_latency = Histogram(
                'pipeline_heavy_stage_latency_ms',
                'Latency for heavy stages only (ms)',
                ['stage']
            )
            cls.pipeline_confidence = Histogram(
                'pipeline_confidence_progress',
                'Confidence value after each stage',
                ['stage']
            )
            cls.pipeline_events = Counter(
                'pipeline_events_total',
                'Total events processed through pipeline',
                ['terminal']
            )
            cls.stage_exec_counter = Counter(
                'pipeline_stage_executions_total',
                'Total executions per pipeline stage',
                ['stage']
            )
            cls.stage_skip_counter = Counter(
                'pipeline_stage_skips_total',
                'Total skips per pipeline stage',
                ['stage', 'reason']
            )
            cls.allowlist_hits = Counter(
                'pipeline_allowlist_hits_total',
                'Events adjusted by pipeline allowlists',
                ['category']
            )
            cls.groundtruth_outcomes = Counter(
                'pipeline_groundtruth_outcome_total',
                'Ground truth comparison outcomes',
                ['outcome']
            )
            cls.confidence_bucket_counter = Counter(
                'pipeline_confidence_bucket_total',
                'Final pipeline confidence bucket counts',
                ['bucket']
            )
            cls.parent_child_counter = Counter(
                'suspicious_parent_child_total',
                'Count of suspicious parent-child process relationships detected'
            )
            cls.beacon_counter = Counter(
                'beacon_detection_total',
                'Count of beacon heuristic detections'
            )
            cls.breaker_state_gauge = Gauge(
                'pipeline_breaker_disabled',
                'Circuit breaker state (1=disabled, 0=enabled)',
            )
            cls.breaker_fallback_counter = Counter(
                'pipeline_breaker_fallback_total',
                'Fallback activations triggered by the circuit breaker',
                ['source', 'status']
            )
        finally:
            cls._initialized = True

    @classmethod
    def ensure_memory_metrics(cls) -> None:
        if cls.rss_gauge is not None:
            return
        try:
            from prometheus_client import Counter, Gauge  # type: ignore
        except Exception:
            return
        with contextlib.suppress(Exception):
            cls.rss_gauge = Gauge('process_rss_mb', 'Process RSS (MB)')
        with contextlib.suppress(Exception):
            cls.mem_trip_total = Counter(
                'memory_circuit_trips_total',
                'Memory circuit breaker trips',
                ['action']
            )

    def record_stage(self, stage: str, duration_ms: float, confidence: float, *, heavy: bool = False) -> None:
        if self.stage_latency:
            with contextlib.suppress(Exception):
                self.stage_latency.labels(stage=stage).observe(duration_ms)
        if heavy and self.heavy_stage_latency:
            with contextlib.suppress(Exception):
                self.heavy_stage_latency.labels(stage=stage).observe(duration_ms)
        if self.pipeline_confidence:
            with contextlib.suppress(Exception):
                self.pipeline_confidence.labels(stage=stage).observe(confidence)

    def record_stage_execution(self, stage: str) -> None:
        if self.stage_exec_counter:
            with contextlib.suppress(Exception):
                self.stage_exec_counter.labels(stage=stage).inc()

    def record_stage_skip(self, stage: str, reason: str) -> None:
        if self.stage_skip_counter:
            with contextlib.suppress(Exception):
                self.stage_skip_counter.labels(stage=stage, reason=reason).inc()

    def record_breaker_state(self, disabled: bool) -> None:
        gauge = self.__class__.breaker_state_gauge
        if gauge:
            with contextlib.suppress(Exception):
                gauge.set(1 if disabled else 0)

    def record_breaker_fallback(self, source: str, success: bool) -> None:
        counter = self.__class__.breaker_fallback_counter
        if counter:
            status = 'ok' if success else 'error'
            with contextlib.suppress(Exception):
                counter.labels(source=source, status=status).inc()

    def increment_pipeline_events(self, terminal: bool) -> None:
        if self.pipeline_events:
            with contextlib.suppress(Exception):
                self.pipeline_events.labels(terminal=str(terminal).lower()).inc()

    def increment_parent_child(self) -> None:
        if self.parent_child_counter:
            with contextlib.suppress(Exception):
                self.parent_child_counter.inc()

    def increment_beacon(self) -> None:
        if self.beacon_counter:
            with contextlib.suppress(Exception):
                self.beacon_counter.inc()

    def record_allowlist_hit(self, category: str) -> None:
        if self.allowlist_hits:
            with contextlib.suppress(Exception):
                self.allowlist_hits.labels(category=category).inc()

    def record_confidence_bucket(self, confidence: float) -> None:
        if not self.confidence_bucket_counter:
            return
        bucket = self._bucket_for(confidence)
        with contextlib.suppress(Exception):
            self.confidence_bucket_counter.labels(bucket=bucket).inc()

    @staticmethod
    def _bucket_for(confidence: float) -> str:
        if confidence < 0.1:
            return '<0.1'
        if confidence < 0.25:
            return '0.1-0.25'
        if confidence < 0.5:
            return '0.25-0.5'
        if confidence < 0.75:
            return '0.5-0.75'
        if confidence < 0.9:
            return '0.75-0.9'
        return '>=0.9'

    def set_rss(self, rss_mb: float) -> None:
        if self.__class__.rss_gauge:
            with contextlib.suppress(Exception):
                self.__class__.rss_gauge.set(rss_mb)

    def record_mem_trip(self, action: str) -> None:
        if self.__class__.mem_trip_total:
            with contextlib.suppress(Exception):
                self.__class__.mem_trip_total.labels(action=action).inc()

