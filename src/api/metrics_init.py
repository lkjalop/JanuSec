"""Metrics initialization module.
Provides idempotent registration and exposes metric variables for import.
"""
from __future__ import annotations
from typing import Any
import os
import logging

logger = logging.getLogger(__name__)

try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram  # type: ignore
    REGISTRY = CollectorRegistry(auto_describe=True)
except Exception:  # pragma: no cover
    Counter = Gauge = Histogram = None  # type: ignore
    REGISTRY = None  # type: ignore

# Exposed metrics (populated on ensure_metrics())
delivery_attempts = None
dead_letter_gauge = None
ingest_events_counter = None
ingest_failures_counter = None
ingest_buffer_gauge = None
alert_ring_util_gauge = None
ingest_latency_hist = None
ingest_validation_errors = None
decisions_counter = None
notifications_counter = None
escalations_counter = None

_initialized = False

def _safe_counter(name: str, desc: str, labels: list[str] | None = None):
    if Counter and REGISTRY:
        try:
            return Counter(name, desc, labels or [], registry=REGISTRY)
        except ValueError:  # already registered
            return Counter(name, desc, labels or [])  # separate singleton reuse
    class _Stub:
        def labels(self,*a,**k): return self
        def inc(self,*a,**k): return None
        def observe(self,*a,**k): return None
        def set(self,*a,**k): return None
    return _Stub()

def _safe_gauge(name: str, desc: str, labels: list[str] | None = None):
    if Gauge and REGISTRY:
        try:
            return Gauge(name, desc, labels or [], registry=REGISTRY)
        except ValueError:
            return Gauge(name, desc, labels or [])
    class _Stub:
        def labels(self,*a,**k): return self
        def set(self,*a,**k): return None
    return _Stub()

def _safe_hist(name: str, desc: str, labels: list[str] | None = None):
    if Histogram and REGISTRY:
        try:
            return Histogram(name, desc, labels or [], registry=REGISTRY)
        except ValueError:
            return Histogram(name, desc, labels or [])
    class _Stub:
        def observe(self,*a,**k): return None
    return _Stub()

def ensure_metrics() -> None:
    global _initialized, delivery_attempts, dead_letter_gauge, ingest_events_counter, ingest_failures_counter
    global ingest_buffer_gauge, alert_ring_util_gauge, ingest_latency_hist, ingest_validation_errors
    global decisions_counter, notifications_counter, escalations_counter
    if _initialized:
        return
    delivery_attempts = _safe_counter('notification_delivery_attempts_total','Notification delivery attempts',['target','outcome'])
    dead_letter_gauge = _safe_gauge('notification_dead_letter_items','Dead letter queue size',['target'])
    ingest_events_counter = _safe_counter('events_ingested_total','Events ingested by source',['source'])
    ingest_failures_counter = _safe_counter('ingest_failures_total','Failed ingested events',['reason'])
    ingest_buffer_gauge = _safe_gauge('ingest_buffer_size','Current in-memory event buffer size')
    alert_ring_util_gauge = _safe_gauge('alert_ring_utilization','Fraction of alert ring used')
    ingest_latency_hist = _safe_hist('ingest_decision_latency_seconds','Latency from batch ingest start to classification decision')
    ingest_validation_errors = _safe_counter('ingest_validation_errors_total','Validation errors during batch ingest',['field'])
    decisions_counter = _safe_counter('decisions_total','Total classification decisions',['verdict'])
    notifications_counter = _safe_counter('notifications_sent_total','Notifications dispatched',['channel','outcome'])
    escalations_counter = _safe_counter('escalations_total','Total escalations dispatched',['reason'])
    _initialized = True
    logger.info("Metrics initialized (registry=%s)", bool(REGISTRY))

__all__ = [
    'ensure_metrics','delivery_attempts','dead_letter_gauge','ingest_events_counter','ingest_failures_counter',
    'ingest_buffer_gauge','alert_ring_util_gauge','ingest_latency_hist','ingest_validation_errors',
    'decisions_counter','notifications_counter','escalations_counter','REGISTRY'
]
