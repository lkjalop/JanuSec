"""False positive & ingestion quality metrics aggregation.

Provides counters/gauges for precision tracking and suppression rule usage.
Lightweight; integrates with Prometheus if available else no-op stubs.
"""
from __future__ import annotations

try:  # pragma: no cover
    from prometheus_client import Counter, Gauge  # type: ignore
except Exception:  # pragma: no cover
    class _MetricShim:
        """No-op shim when prometheus_client is unavailable."""

        def __init__(self,*_a,**_k) -> None:
            pass
        def labels(self,*_a,**_k):
            return self
        def inc(self,*_a,**_k) -> None:
            return None
        def set(self,*_a,**_k) -> None:
            return None

    Counter = Gauge = _MetricShim  # type: ignore

precision_events_total = Counter('precision_events_total','Events counted for precision',['label'])  # label=tp|fp
suppression_rule_usage_total = Counter('suppression_rule_usage_total','Suppression rule applications',['template','action'])
mapping_coverage_ratio = Gauge('mapping_coverage_ratio','Fraction of canonical fields mapped (0-1)',['source_type'])

def record_label(tp: bool) -> None:
    try:
        precision_events_total.labels(label='tp' if tp else 'fp').inc()
    except Exception:
        pass

def record_mapping_coverage(source_type: str, mapped: int, total: int) -> None:
    if total <= 0:
        return
    ratio = max(0.0, min(1.0, mapped / float(total)))
    try:
        mapping_coverage_ratio.labels(source_type=source_type).set(ratio)
    except Exception:
        pass

__all__ = ['record_label','record_mapping_coverage']
