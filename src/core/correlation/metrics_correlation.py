"""Correlation metrics lightweight collector.

Exposes idempotent registration helpers for correlation-layer counters:
  - temporal_matches_total (labels: pattern)
  - suppression_hits_total (labels: template, action)
  - cooccurrence_pairs_total (no labels)
  - state_persist_ops_total (labels: op)
  - negative_pattern_hits_total (labels: pattern)

All counters are best-effort: if prometheus_client is missing or test-mode is
enabled they degrade to in-memory stubs (mirroring src.api.metrics_init helpers).

Public API:
  ensure_corr_metrics()
  inc_temporal(pattern: str)
  inc_suppression(template: str, action: str)
  inc_cooccurrence_pairs(count: int)
  inc_state_persist(op: str)
  inc_negative(pattern: str)

Imported cheaply from correlation modules; each function guards its own
initialization so hot paths remain low overhead.
"""
from __future__ import annotations

import os
from typing import Any

try:
    from src.api.metrics_init import _safe_counter, ensure_metrics  # type: ignore
except Exception:  # pragma: no cover
    _safe_counter = None  # type: ignore
    ensure_metrics = lambda: None  # type: ignore

_initialized = False
_C_TEMPORAL: Any = None
_C_SUPPRESSION: Any = None
_C_COOCCURRENCE: Any = None
_C_STATE: Any = None
_C_NEGATIVE: Any = None

def ensure_corr_metrics() -> None:
    global _initialized, _C_TEMPORAL, _C_SUPPRESSION, _C_COOCCURRENCE, _C_STATE, _C_NEGATIVE
    if _initialized:
        return
    try:
        ensure_metrics()
    except Exception:
        pass
    try:
        if _safe_counter is not None:
            _C_TEMPORAL = _safe_counter('correlation_temporal_matches_total','Temporal pattern matches',['pattern'])
            _C_SUPPRESSION = _safe_counter('correlation_suppression_hits_total','Suppression template matches',['template','action'])
            _C_COOCCURRENCE = _safe_counter('correlation_cooccurrence_pairs_total','Co-occurrence pair updates', [])
            _C_STATE = _safe_counter('correlation_state_persist_ops_total','Correlation state persistence ops',['op'])
            _C_NEGATIVE = _safe_counter('correlation_negative_pattern_hits_total','Negative benign pattern matches',['pattern'])
    except Exception:
        pass
    _initialized = True

def inc_temporal(pattern: str) -> None:
    try:
        ensure_corr_metrics(); _C_TEMPORAL.labels(pattern=pattern).inc()
    except Exception:
        pass

def inc_suppression(template: str, action: str) -> None:
    try:
        ensure_corr_metrics(); _C_SUPPRESSION.labels(template=template, action=action).inc()
    except Exception:
        pass

def inc_cooccurrence_pairs(count: int = 1) -> None:
    try:
        ensure_corr_metrics(); _C_COOCCURRENCE.inc(max(1,int(count)))
    except Exception:
        pass

def inc_state_persist(op: str) -> None:
    try:
        ensure_corr_metrics(); _C_STATE.labels(op=op).inc()
    except Exception:
        pass

def inc_negative(pattern: str) -> None:
    try:
        ensure_corr_metrics(); _C_NEGATIVE.labels(pattern=pattern).inc()
    except Exception:
        pass

__all__ = [
    'ensure_corr_metrics','inc_temporal','inc_suppression','inc_cooccurrence_pairs','inc_state_persist','inc_negative'
]
