from __future__ import annotations
from typing import Any
from src.api.metrics_init import _safe_counter, ensure_metrics

_initialized = False

def ensure_correlation_metrics() -> None:
    global _initialized
    if _initialized:
        return
    try:
        ensure_metrics()
    except Exception:
        pass
    # Per-rule counters
    _safe_counter('correlation_rule_hits_total', 'Correlation rule hits', ['rule'])
    _safe_counter('correlation_rule_suppressed_total', 'Correlation rule suppressed events', ['rule'])
    _initialized = True

def rule_hit(rule_name: str) -> None:
    try:
        ensure_correlation_metrics()
        c = _safe_counter('correlation_rule_hits_total','Correlation rule hits',['rule'])
        c.labels(rule=rule_name).inc()
    except Exception:
        pass

def rule_suppressed(rule_name: str) -> None:
    try:
        ensure_correlation_metrics()
        c = _safe_counter('correlation_rule_suppressed_total','Correlation rule suppressed events',['rule'])
        c.labels(rule=rule_name).inc()
    except Exception:
        pass
