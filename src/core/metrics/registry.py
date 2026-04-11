"""Unified metrics registry & helper factories.

Provides consistent naming and a single CollectorRegistry. Existing modules can
migrate gradually; legacy metrics remain until deprecated.
"""
from __future__ import annotations

import os
import threading
from collections.abc import Iterable
from typing import Dict, Optional, Any

try:
    from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram  # type: ignore
except Exception:  # pragma: no cover
    class _CollectorShim:
        """Minimal CollectorRegistry replacement when prometheus_client is missing."""
        def __init__(self,*_a,**_k) -> None:
            self._dummy_samples = {}
            self._names_to_collectors = {}
        def collect(self):
            return []

    class _MetricShim:  # type: ignore
        def __init__(self,*_a,**_k) -> None:
            pass
        def labels(self,*_a,**_k):
            return self
        def inc(self,*_a,**_k) -> None:
            return None
        def observe(self,*_a,**_k) -> None:
            return None
        def set(self,*_a,**_k) -> None:
            return None

    CollectorRegistry = _CollectorShim  # type: ignore
    Counter = Histogram = Gauge = _MetricShim  # type: ignore

_LOCK = threading.Lock()
_REGISTRY: Any | None = None

DEFAULT_NAMESPACE = os.getenv('METRICS_NAMESPACE','janusec')

_EXPECTED: dict[str,str] = {}  # metric_name -> kind ('counter','gauge','histogram')


def get_registry() -> Any:
    global _REGISTRY
    with _LOCK:
        if _REGISTRY is None and isinstance(CollectorRegistry, type):  # real impl
            # Prefer the app-level registry if available to ensure all metrics
            # are exposed via the same /metrics endpoint
            APP_REG = None
            # Try src.api.metrics_init first (project structure), then fallback
            try:
                from src.api.metrics_init import REGISTRY as _APP_REG  # type: ignore
                APP_REG = _APP_REG
            except Exception:
                try:
                    from src.api.metrics_init import REGISTRY as _APP_REG  # type: ignore
                    APP_REG = _APP_REG
                except Exception:
                    APP_REG = None
            if APP_REG is not None:
                _REGISTRY = APP_REG
            else:
                _REGISTRY = CollectorRegistry(auto_describe=True)  # type: ignore
        if _REGISTRY is None:  # fallback stub
            class _Dummy:  # pragma: no cover
                def collect(self): return []
            _REGISTRY = _Dummy()  # type: ignore
        return _REGISTRY  # type: ignore


def _register_expected(name: str, kind: str):
    _EXPECTED[name] = kind


def metric_counter(component: str, what: str, desc: str, labels: Iterable[str] | None = None, namespace: str = DEFAULT_NAMESPACE):
    name = f"{namespace}_{component}_{what}_total"
    reg = get_registry()
    # Ensure a reusable map exists on the registry to avoid duplicate creations
    try:
        if not hasattr(reg, '_names_to_collectors'):
            setattr(reg, '_names_to_collectors', {})
    except Exception:
        pass
    try:
        c = Counter(name, desc, list(labels or []), registry=reg)  # type: ignore
        # Store for reuse on subsequent calls
        try:
            reg._names_to_collectors[name] = c
        except Exception:
            pass
    except Exception:  # already exists or stub
        # Try to reuse existing collector from this registry
        try:
            existing = getattr(reg, '_names_to_collectors', {}).get(name)
            if existing:
                c = existing  # type: ignore
            else:
                # As a last resort, return a Counter bound to reg via no-op wrapper
                c = Counter(name, desc, list(labels or []), registry=reg)  # type: ignore
                try:
                    reg._names_to_collectors[name] = c
                except Exception:
                    pass
        except Exception:
            # Fallback: create a detached stub-like counter (no-op in tests)
            c = Counter(name, desc, list(labels or []))
    _register_expected(name,'counter')
    # In lightweight test environments, forward increments into reg._dummy_samples
    try:
        if hasattr(reg, '_dummy_samples'):
            class _ForwardCounter:
                def labels(self, *a, **kw):
                    lab = {}
                    try:
                        if kw:
                            lab = dict(kw)
                        elif a:
                            for i, v in enumerate(a):
                                lab[f'arg{i}'] = v
                    except Exception:
                        lab = {}
                    class _L:
                        def __init__(self, n, labels, store):
                            self._n = n
                            self._labels = labels or {}
                            self._store = store
                        def inc(self, v=1):
                            try:
                                samples = self._store.setdefault(name, [])
                                samples.append(type('S', (), {'name': name, 'labels': self._labels, 'value': float(v)})())
                            except Exception:
                                return None
                    return _L(name, lab, reg._dummy_samples)
            # Store named collector for reuse
            try:
                reg._names_to_collectors[name] = _ForwardCounter()
            except Exception:
                pass
            return reg._names_to_collectors.get(name) or _ForwardCounter()
    except Exception:
        pass
    return c


def metric_gauge(component: str, what: str, desc: str, labels: Iterable[str] | None = None, namespace: str = DEFAULT_NAMESPACE):
    name = f"{namespace}_{component}_{what}"
    reg = get_registry()
    # Ensure a reusable map exists on the registry to avoid duplicate creations
    try:
        if not hasattr(reg, '_names_to_collectors'):
            setattr(reg, '_names_to_collectors', {})
    except Exception:
        pass
    try:
        g = Gauge(name, desc, list(labels or []), registry=reg)  # type: ignore
        # Store for reuse on subsequent calls
        try:
            reg._names_to_collectors[name] = g
        except Exception:
            pass
    except Exception:
        try:
            existing = getattr(reg, '_names_to_collectors', {}).get(name)
            if existing:
                g = existing  # type: ignore
            else:
                g = Gauge(name, desc, list(labels or []), registry=reg)  # type: ignore
                try:
                    reg._names_to_collectors[name] = g
                except Exception:
                    pass
        except Exception:
            g = Gauge(name, desc, list(labels or []))
    _register_expected(name,'gauge')
    # In lightweight test environments, forward sets into reg._dummy_samples
    try:
        if hasattr(reg, '_dummy_samples'):
            class _ForwardGauge:
                def set(self, v=0):
                    try:
                        reg._dummy_samples[name] = [type('S', (), {'name': name, 'labels': {}, 'value': float(v)})()]
                    except Exception:
                        return None

                def labels(self, *a, **kw):
                    lab = {}
                    try:
                        if kw:
                            lab = dict(kw)
                        elif a:
                            for i, v in enumerate(a):
                                lab[f'arg{i}'] = v
                    except Exception:
                        lab = {}
                    class _L:
                        def __init__(self, n, labels, store):
                            self._n = n
                            self._labels = labels or {}
                            self._store = store
                        def set(self, v=0):
                            try:
                                # Replace existing sample list with latest value to ensure tests read current value
                                self._store[name] = [type('S', (), {'name': name, 'labels': self._labels, 'value': float(v)})()]
                            except Exception:
                                return None
                    return _L(name, lab, reg._dummy_samples)
            try:
                reg._names_to_collectors[name] = _ForwardGauge()
            except Exception:
                pass
            return reg._names_to_collectors.get(name) or _ForwardGauge()
    except Exception:
        pass
    return g


def metric_histogram(component: str, what: str, desc: str, labels: Iterable[str] | None = None, namespace: str = DEFAULT_NAMESPACE, unit_seconds: bool = True):
    suffix = '_seconds' if unit_seconds else '_ms'
    name = f"{namespace}_{component}_{what}{suffix}"
    reg = get_registry()
    # Ensure a reusable map exists on the registry to avoid duplicate creations
    try:
        if not hasattr(reg, '_names_to_collectors'):
            setattr(reg, '_names_to_collectors', {})
    except Exception:
        pass
    try:
        h = Histogram(name, desc, list(labels or []), registry=reg)  # type: ignore
        # Store for reuse on subsequent calls
        try:
            reg._names_to_collectors[name] = h
        except Exception:
            pass
    except Exception:
        try:
            existing = getattr(reg, '_names_to_collectors', {}).get(name)
            if existing:
                h = existing  # type: ignore
            else:
                h = Histogram(name, desc, list(labels or []), registry=reg)  # type: ignore
                try:
                    reg._names_to_collectors[name] = h
                except Exception:
                    pass
        except Exception:
            h = Histogram(name, desc, list(labels or []))
    _register_expected(name,'histogram')
    # In lightweight test environments, forward observes into reg._dummy_samples
    try:
        if hasattr(reg, '_dummy_samples'):
            class _ForwardHist:
                def labels(self, *a, **kw):
                    lab = {}
                    try:
                        if kw:
                            lab = dict(kw)
                        elif a:
                            for i, v in enumerate(a):
                                lab[f'arg{i}'] = v
                    except Exception:
                        lab = {}
                    class _L:
                        def __init__(self, n, labels, store):
                            self._n = n
                            self._labels = labels or {}
                            self._store = store
                        def observe(self, v=0):
                            try:
                                samples = self._store.setdefault(name, [])
                                samples.append(type('S', (), {'name': name, 'labels': self._labels, 'value': float(v)})())
                            except Exception:
                                return None
                    return _L(name, lab, reg._dummy_samples)
            try:
                reg._names_to_collectors[name] = _ForwardHist()
            except Exception:
                pass
            return reg._names_to_collectors.get(name) or _ForwardHist()
    except Exception:
        pass
    return h


def ensure_tenant_labels(labels: Iterable[str] | None, include_tenant: bool = True) -> list[str]:
    """Return a labels list that includes 'tenant' when include_tenant True.

    This lets callers create metric families with an optional tenant label
    dimension in a consistent way.
    """
    out = list(labels or [])
    if include_tenant and 'tenant' not in out:
        out.append('tenant')
    return out


def normalize_emit_labels(base: dict, tenant: str | None) -> dict:
    """Return a labels dict for emission that always contains 'tenant'.

    If tenant is falsy, use empty string as the sentinel value. This keeps
    label dimensions stable while allowing cardinality guards to be applied
    at emit time by higher-level helpers.
    """
    out = dict(base or {})
    out['tenant'] = str(tenant) if tenant else ''
    return out


def expected_metrics() -> dict[str,str]:
    return dict(_EXPECTED)

__all__ = [
    'get_registry','metric_counter','metric_gauge','metric_histogram','expected_metrics','DEFAULT_NAMESPACE'
]
