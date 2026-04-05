"""Pipeline stage instrumentation utilities.

Provides simple wrappers to record per-stage latency and status and expose a
snapshot suitable for API consumption & Prometheus metrics.
"""
from __future__ import annotations
import time
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from prometheus_client import Histogram, Counter  # type: ignore
except Exception:  # pragma: no cover
    Histogram = Counter = None  # type: ignore

# Prometheus metric singletons (lazy init)
_PIPELINE_STAGE_LATENCY: Any = None
_PIPELINE_STAGE_RUNS: Any = None

_INIT_LOCK = threading.Lock()

def _ensure_metrics() -> None:
    global _PIPELINE_STAGE_LATENCY, _PIPELINE_STAGE_RUNS
    if _PIPELINE_STAGE_LATENCY is not None and _PIPELINE_STAGE_RUNS is not None:
        return
    with _INIT_LOCK:
        if _PIPELINE_STAGE_LATENCY is None and Histogram is not None:
            try:
                _PIPELINE_STAGE_LATENCY = Histogram(
                    'pipeline_stage_latency_seconds',
                    'Latency per pipeline stage',
                    ['stage']
                )
            except Exception:
                _PIPELINE_STAGE_LATENCY = None
        if _PIPELINE_STAGE_RUNS is None and Counter is not None:
            try:
                _PIPELINE_STAGE_RUNS = Counter(
                    'pipeline_stage_outcomes_total',
                    'Pipeline stage run outcomes',
                    ['stage','status']
                )
            except Exception:
                _PIPELINE_STAGE_RUNS = None

# In-memory recent runs store (bounded)
_MAX_RUNS = 200
_PIPELINE_RUNS: List[Dict[str, Any]] = []
_RUN_LOCK = threading.Lock()
_RUN_TENANTS: Dict[str, str | None] = {}

def start_pipeline_run(run_id: Optional[str] = None, tenant: str | None = None) -> str:
    """Start a pipeline run and optionally persist a tenant partition record.

    If `tenant` is provided, a minimal partition file will be written so runtime
    can recover per-tenant partitions on restart.
    """
    rid = run_id or f"run-{int(time.time()*1000)}"
    with _RUN_LOCK:
        _PIPELINE_RUNS.append({'run_id': rid, 'stages': [], 'started_ts': time.time()})
        # store tenant mapping for this run
        _RUN_TENANTS[rid] = tenant
        if len(_PIPELINE_RUNS) > _MAX_RUNS:
            del _PIPELINE_RUNS[0: len(_PIPELINE_RUNS)-_MAX_RUNS]
    # Best-effort persistence hook to create tenant partition directory
    if tenant:
        try:
            try:
                from src.core.tenant_store import persist_tenant_partition
            except Exception:
                persist_tenant_partition = None
            if persist_tenant_partition:
                try:
                    persist_tenant_partition(tenant, {'last_run_id': rid, 'started_ts': time.time()})
                except Exception:
                    pass
        except Exception:
            pass
    return rid

class StageContext:
    def __init__(self, run_id: str, stage: str):
        self.run_id = run_id
        self.stage = stage
        self.start_ts: float = 0.0
        self.end_ts: float = 0.0
        self.status: str = 'unknown'
        self.error: str | None = None
    def __enter__(self):
        self.start_ts = time.time()
        return self
    def __exit__(self, exc_type, exc, tb):
        self.end_ts = time.time()
        if exc_type is None:
            self.status = 'success'
        else:
            self.status = 'error'
            try:
                self.error = str(exc)
            except Exception:
                self.error = 'error'
        dur = self.end_ts - self.start_ts
        try:
            _ensure_metrics()
            # Attempt tenant-aware metric emission using emit_labels_with_guard
            try:
                try:
                    from .metrics_tenant_helper import emit_labels_with_guard  # type: ignore
                except Exception:
                    emit_labels_with_guard = None
                tenant_label = None
                try:
                    tenant_label = _RUN_TENANTS.get(self.run_id)
                except Exception:
                    tenant_label = None
                if _PIPELINE_STAGE_LATENCY is not None:
                    if emit_labels_with_guard:
                        try:
                            labels = emit_labels_with_guard(None, {'stage': self.stage}, tenant_label)
                            _PIPELINE_STAGE_LATENCY.labels(**labels).observe(dur)
                        except Exception:
                            try:
                                _PIPELINE_STAGE_LATENCY.labels(stage=self.stage).observe(dur)
                            except Exception:
                                pass
                    else:
                        try:
                            _PIPELINE_STAGE_LATENCY.labels(stage=self.stage).observe(dur)
                        except Exception:
                            pass
                if _PIPELINE_STAGE_RUNS is not None:
                    if emit_labels_with_guard:
                        try:
                            labels = emit_labels_with_guard(None, {'stage': self.stage, 'status': self.status}, tenant_label)
                            _PIPELINE_STAGE_RUNS.labels(**labels).inc()
                        except Exception:
                            try:
                                _PIPELINE_STAGE_RUNS.labels(stage=self.stage, status=self.status).inc()
                            except Exception:
                                pass
                    else:
                        try:
                            _PIPELINE_STAGE_RUNS.labels(stage=self.stage, status=self.status).inc()
                        except Exception:
                            pass
            except Exception:
                # metrics emission best-effort — swallow
                pass
        except Exception:
            pass
        # Append to run snapshot
        with _RUN_LOCK:
            for r in reversed(_PIPELINE_RUNS):
                if r.get('run_id') == self.run_id:
                    r['stages'].append({
                        'name': self.stage,
                        'started_ts': self.start_ts,
                        'ended_ts': self.end_ts,
                        'duration': dur,
                        'status': self.status,
                        **({'error': self.error} if self.error else {})
                    })
                    break
        # Do not suppress exceptions
        return False

def stage(run_id: str, name: str):
    """Context manager entry for manual with-style usage.
    Example:
        with stage(run_id, 'normalize'):
            ...
    """
    return StageContext(run_id, name)

def run_stage(run_id: str, name: str, fn: Callable[..., Any], *a, **k) -> Any:
    """Execute fn inside a stage context and return its result."""
    with stage(run_id, name):
        return fn(*a, **k)

def snapshot(run_id: str) -> Dict[str, Any] | None:
    with _RUN_LOCK:
        for r in reversed(_PIPELINE_RUNS):
            if r.get('run_id') == run_id:
                return {
                    'run_id': run_id,
                    'started_ts': r.get('started_ts'),
                    'stages': list(r.get('stages') or [])
                }
    return None

def recent_runs(limit: int = 20) -> List[Dict[str, Any]]:
    with _RUN_LOCK:
        return list(reversed(_PIPELINE_RUNS[-limit:]))

__all__ = [
    'start_pipeline_run','stage','run_stage','snapshot','recent_runs'
]
