"""Lightweight metrics instrumentation wrapper.
Provides Prometheus metrics with safe no-op fallbacks when prometheus_client
is not installed (so code can run without hard dependency during CI/dev).
This module is the package initializer so `core.metrics` is a package and
`core.metrics.registry` can also be imported.
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
        try:
            return Counter(name, description)
        except ValueError:
            return _noop()
    return _noop()


def make_histogram(name: str, description: str, buckets: list | None = None):
    if PROMETHEUS_AVAILABLE:
        try:
            if buckets:
                return Histogram(name, description, buckets=buckets)
            return Histogram(name, description)
        except ValueError:
            return _noop()
    return _noop()


def make_gauge(name: str, description: str):
    if PROMETHEUS_AVAILABLE:
        try:
            return Gauge(name, description)
        except ValueError:
            return _noop()
    return _noop()

__all__ = ['make_counter', 'make_histogram', 'make_gauge', 'PROMETHEUS_AVAILABLE']
