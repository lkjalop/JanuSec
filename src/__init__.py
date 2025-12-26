from __future__ import annotations

import os
import sys
import types
import asyncio
import threading

# Minimal init shim to avoid import-time side effects during tests.
_lite = (
    os.environ.get('PLATFORM_LITE_INIT') == '1'
    or os.environ.get('TEST_HELPERS_ENABLED') == '1'
    or 'PYTEST_CURRENT_TEST' in os.environ
)
if _lite and 'prometheus_client' not in sys.modules:
    _prom = types.ModuleType('prometheus_client')
    class _Registry:
        def __init__(self, *args, **kwargs):
            pass

        def collect(self):
            return []
    def _make_dummy(name):
        class Dummy:
            def __init__(self, *a, **k):
                self._name = name
            def inc(self, v=1, labels=None):
                return None
            def labels(self, **labels):
                return self
            def observe(self, v, labels=None):
                return None
        return Dummy
    _prom.CollectorRegistry = _Registry
    _prom.REGISTRY = _Registry()
    # Provide lightweight factory functions matching prometheus_client API
    def _factory_counter(*a, **k):
        return _make_dummy(a[0] if a else 'counter')()
    def _factory_histogram(*a, **k):
        return _make_dummy(a[0] if a else 'hist')()
    def _factory_gauge(*a, **k):
        # Gauges support .labels(...).set(value)
        class _Gauge:
            def __init__(self, *a, **k):
                self._name = a[0] if a else 'gauge'
            def labels(self, *a, **k):
                return self
            def set(self, v=0):
                return None
            def set_function(self, fn):
                return None
        return _Gauge()
    _prom.Counter = _factory_counter
    _prom.Histogram = _factory_histogram
    _prom.Gauge = _factory_gauge
    _prom.generate_latest = lambda reg=None: b""
    sys.modules['prometheus_client'] = _prom

try:
    try:
        _ = asyncio.get_event_loop()
    except RuntimeError:
        if threading.current_thread() is threading.main_thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
except Exception:
    pass

try:
    from .. import database_adapter  # type: ignore
except Exception:
    try:
        import database_adapter  # type: ignore
    except Exception:
        pass
