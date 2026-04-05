from __future__ import annotations

from typing import Any, Dict

try:
    from prometheus_client import Counter, Gauge, Histogram  # type: ignore
except Exception:  # pragma: no cover
    Counter = Gauge = Histogram = None  # type: ignore

try:
    from src.api.metrics_init import REGISTRY  # type: ignore
except Exception:  # pragma: no cover
    REGISTRY = None  # type: ignore

_inited = False
_transitions: Any = None
_state_count: Any = None
_event_flags: Any = None
_risk_hist: Any = None
_config_version: Any = None
_ewma_updates: Any = None
_ewma_boost: Any = None
_ewma_residual_raw: Any = None
_ewma_residual_norm: Any = None
_latency_hist_update: Any = None
_latency_hist_prune: Any = None
_latency_hist_path: Any = None


def _counter(name: str, desc: str, labels: list[str] | None = None) -> Any:
    if Counter is None:
        class _Stub:
            def labels(self,*a,**k): return self
            def inc(self,*a,**k): return None
        return _Stub()
    try:
        return Counter(name, desc, labels or [], registry=REGISTRY)
    except Exception:
        return Counter(name, desc, labels or [])


def _gauge(name: str, desc: str, labels: list[str] | None = None) -> Any:
    if Gauge is None:
        class _Stub:
            def labels(self,*a,**k): return self
            def set(self,*a,**k): return None
        return _Stub()
    try:
        return Gauge(name, desc, labels or [], registry=REGISTRY)
    except Exception:
        return Gauge(name, desc, labels or [])


def _hist(name: str, desc: str, labels: list[str] | None = None) -> Any:
    if Histogram is None:
        class _Stub:
            def labels(self,*a,**k): return self
            def observe(self,*a,**k): return None
        return _Stub()
    try:
        return Histogram(name, desc, labels or [], registry=REGISTRY)
    except Exception:
        return Histogram(name, desc, labels or [])


def ensure_identity_metrics() -> None:
    global _inited, _transitions, _state_count, _event_flags, _risk_hist, _config_version, _ewma_updates, _ewma_boost, _ewma_residual_raw, _ewma_residual_norm, _latency_hist_update, _latency_hist_prune, _latency_hist_path
    if _inited:
        return
    _transitions = _counter('identity_state_transitions_total','Identity state transitions',['from','to'])
    _state_count = _gauge('identity_state_count','Current identities in each state',['state'])
    _event_flags = _counter('identity_event_flags_total','Identity feature flags',['flag'])
    _risk_hist = _hist('identity_risk_score','Identity risk score (0-5)')
    _config_version = _gauge('identity_risk_config_version','Identity risk config version currently active',['hash'])
    _ewma_updates = _counter('identity_ewma_updates_total','Identity EWMA updates total')
    _ewma_boost = _counter('identity_ewma_boost_total','Identity EWMA positive boosts applied')
    _ewma_residual_raw = _hist('identity_ewma_residual_raw','Identity EWMA raw residual')
    _ewma_residual_norm = _hist('identity_ewma_residual_norm','Identity EWMA normalized residual')
    _latency_hist_update = _hist('identity_update_latency_seconds','Identity risk update latency seconds')
    _latency_hist_prune = _hist('identity_prune_latency_seconds','Identity prune latency seconds')
    _latency_hist_path = _hist('identity_path_score_latency_seconds','Identity path scoring latency seconds')
    _inited = True


def record_transition(old: str, new: str) -> None:
    try:
        ensure_identity_metrics()
        _transitions.labels(**{'from': old, 'to': new}).inc()
    except Exception:
        pass


def set_state_counts(counts: Dict[str, int]) -> None:
    try:
        ensure_identity_metrics()
        for st, v in counts.items():
            _state_count.labels(state=st).set(int(v))
    except Exception:
        pass


def record_event_flags(flags: Dict[str, bool]) -> None:
    try:
        ensure_identity_metrics()
        for k, v in flags.items():
            if v:
                _event_flags.labels(flag=k).inc()
    except Exception:
        pass


def observe_risk(score: float) -> None:
    try:
        ensure_identity_metrics()
        _risk_hist.observe(float(score))
    except Exception:
        pass

def set_config_version(hash_: str) -> None:
    try:
        ensure_identity_metrics()
        _config_version.labels(hash=hash_).set(1)
    except Exception:
        pass

def observe_ewma(residual_raw: float, residual_norm: float, boosted: bool) -> None:
    try:
        ensure_identity_metrics()
        _ewma_updates.inc()
        _ewma_residual_raw.observe(float(residual_raw))
        _ewma_residual_norm.observe(float(residual_norm))
        if boosted:
            _ewma_boost.inc()
    except Exception:
        pass

def observe_latency(kind: str, seconds: float) -> None:
    try:
        ensure_identity_metrics()
        if kind == 'update':
            _latency_hist_update.observe(seconds)
        elif kind == 'prune':
            _latency_hist_prune.observe(seconds)
        elif kind == 'path':
            _latency_hist_path.observe(seconds)
    except Exception:
        pass

