"""Minimal telemetry helpers (counters/logging) used by connectors.

This is intentionally lightweight to avoid requiring external metrics backends.
Upgrade by wiring to Prometheus or OpenTelemetry as needed.
"""
import logging
from collections import defaultdict
from typing import Dict

logger = logging.getLogger(__name__)
_counters: Dict[str, int] = defaultdict(int)

# Optional Prometheus export: try to import client, but keep local counters as fallback
_prometheus_available = False
_prom_counters = {}
try:
    from prometheus_client import Counter as PromCounter
    _prometheus_available = True
except Exception:
    _prometheus_available = False


def inc(metric: str, n: int = 1):
    _counters[metric] += n
    logger.debug('metric_inc %s=%s', metric, _counters[metric])
    if _prometheus_available:
        # lazily create Prometheus counters for metric keys
        if metric not in _prom_counters:
            # sanitize metric name to prometheus safe format
            prom_name = metric.replace('.', '_').replace('-', '_') + '_total'
            _prom_counters[metric] = PromCounter(prom_name, f"Prom-exported metric for {metric}")
        _prom_counters[metric].inc(n)


def get_counter(metric: str) -> int:
    return _counters.get(metric, 0)


def dump_counters() -> Dict[str, int]:
    return dict(_counters)
