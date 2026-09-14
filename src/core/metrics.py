"""Lightweight metrics instrumentation wrapper.
Provides Prometheus metrics with safe no-op fallbacks when prometheus_client
is not installed (so code can run without hard dependency during CI dev).
"""
from typing import Optional

try:
    from prometheus_client import Counter, Gauge, Histogram
    PROMETHEUS_AVAILABLE = True
except Exception:
    PROMETHEUS_AVAILABLE = False


def _noop(*args, **kwargs):
    class _Noop:
        def inc(self, *a, **k):
            return

        def observe(self, *a, **k):
            return

        def set(self, *a, **k):
            return

    return _Noop()


def make_counter(name: str, description: str):
    if PROMETHEUS_AVAILABLE:
        return Counter(name, description)
    return _noop()


def make_histogram(name: str, description: str, buckets: list | None = None):
    if PROMETHEUS_AVAILABLE:
        if buckets:
            return Histogram(name, description, buckets=buckets)
        return Histogram(name, description)
    return _noop()


def make_gauge(name: str, description: str):
    if PROMETHEUS_AVAILABLE:
        return Gauge(name, description)
    return _noop()
