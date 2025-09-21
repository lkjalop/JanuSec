"""
Metrics Collector - Centralized metrics collection and export
Author: Security Engineering Team
Version: 1.0.0
"""

import asyncio
import logging
from typing import Dict, Any
from collections import defaultdict
try:
    from prometheus_client import Histogram, Counter
except Exception:  # pragma: no cover
    Histogram = None  # type: ignore
    Counter = None  # type: ignore


class MetricsCollector:
    """Centralized metrics collection and export"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Metrics storage
        self.counters = defaultdict(int)
        self.gauges = defaultdict(float)
        self.histograms = defaultdict(list)
        
        # Performance tracking
        self.events_processed = 0
        self.processing_times = []
        # Additional counters (extended instrumentation)
        self.counters['alerts_generated_total'] = 0
        self.counters['slack_failures_total'] = 0
        self.counters['fallback_tier_usage_total'] = 0
        self.counters['action_failures_total'] = 0
        self.counters['redactions_total'] = 0
        self.counters['factor_feedback_up_total'] = 0
        self.counters['factor_feedback_down_total'] = 0
        # Drift / embedding metrics placeholders
        self.gauges['embedding_avg_norm'] = 0.0
        self.gauges['factor_embedding_drift'] = 0.0
        # Prometheus metrics (singleton style)
        self._init_prometheus()

    def _init_prometheus(self):
        if getattr(self.__class__, '_prom_init', False):
            return
        if Histogram is None:
            return
        try:
            self.__class__.decision_latency = Histogram(
                'decision_latency_ms', 'End-to-end decision latency (ms)'
            )
            self.__class__._prom_init = True
        except Exception:
            pass
    
    async def initialize(self):
        """Initialize metrics collector"""
        self.logger.info("Metrics collector initialized")
    
    async def record_event_ingestion(self, event: Dict[str, Any]):
        """Record event ingestion"""
        self.counters['events_ingested_total'] += 1
    
    async def record_processing_complete(self, result, processing_time: float):
        """Record completed processing"""
        self.events_processed += 1
        self.processing_times.append(processing_time)
        self.counters['events_processed_total'] += 1
        self.counters[f'events_{result.verdict}_total'] += 1
        try:
            if hasattr(self.__class__, 'decision_latency') and self.__class__.decision_latency:
                self.__class__.decision_latency.observe(processing_time)
        except Exception:
            # Fallback in-memory collection
            self.histograms['decision_latency_ms'].append(processing_time)
        
    async def record_processing_error(self, event_id: str, error: str):
        """Record processing error"""
        self.counters['processing_errors_total'] += 1
    
    async def record_health_status(self, status: str):
        """Record health status"""
        self.gauges['system_healthy'] = 1.0 if status == 'healthy' else 0.0
    
    async def record_alert_generated(self, alert_data: Dict[str, Any]):
        """Record alert generation"""
        self.counters['alerts_generated_total'] += 1

    async def record_slack_failure(self):
        self.counters['slack_failures_total'] += 1

    async def record_fallback_tier_usage(self):
        self.counters['fallback_tier_usage_total'] += 1

    async def record_action_failure(self):
        self.counters['action_failures_total'] += 1

    async def record_redaction(self, count: int = 1):
        self.counters['redactions_total'] += count

    async def record_factor_feedback(self, vote: int):
        if vote > 0:
            self.counters['factor_feedback_up_total'] += 1
        elif vote < 0:
            self.counters['factor_feedback_down_total'] += 1

    async def record_embedding_stats(self, avg_norm: float, drift_value: float | None = None):
        self.gauges['embedding_avg_norm'] = avg_norm
        if drift_value is not None:
            self.gauges['factor_embedding_drift'] = drift_value
    
    async def record_system_metrics(self, metrics: Dict[str, Any]):
        """Record system-level metrics"""
        for key, value in metrics.items():
            if isinstance(value, (int, float)):
                self.gauges[key] = float(value)
    
    async def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        return {
            'counters': dict(self.counters),
            'gauges': dict(self.gauges),
            'events_processed': self.events_processed,
            'avg_processing_time': sum(self.processing_times) / len(self.processing_times) if self.processing_times else 0
        }
    
    async def flush_and_shutdown(self):
        """Flush metrics and shutdown"""
        summary = await self.get_metrics_summary()
        self.logger.info(f"Metrics collector shutdown. Final summary: {summary}")