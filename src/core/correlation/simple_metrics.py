from __future__ import annotations
from collections import defaultdict
from typing import Dict, Any

_counters = defaultdict(int)
_score_buckets = defaultdict(lambda: defaultdict(int))

# Attempt to import the central metrics init helpers. If available, ensure
# metrics are created at app startup via ensure_metrics() and use those
# objects for correlation instrumentation. Otherwise fall back to in-process
# counters for unit-test friendliness.
try:
    from src.api.metrics_init import ensure_metrics, REGISTRY
    from src.api.metrics_init import hopgraph_sessions_built_total as _hg_sessions  # noqa: F401
    METRICS_AVAILABLE = True
except Exception:
    ensure_metrics = None  # type: ignore[assignment]
    REGISTRY = None  # type: ignore[assignment]
    METRICS_AVAILABLE = False

# Local handles we expect ensure_metrics() to populate when called at app start
_rule_hits_counter = None
_rule_score_hist = None


def _ensure_local_handles():
    global _rule_hits_counter, _rule_score_hist, METRICS_AVAILABLE
    if METRICS_AVAILABLE and _rule_hits_counter is None:
        try:
            # ensure global metrics are initialized
            ensure_metrics()  # type: ignore[arg-type]
        except Exception:
            pass
        try:
            # Import again; ensure_metrics should have created these globals
            from src.api.metrics_init import hopgraph_sessions_built_total, hopgraph_explanations_generated_total  # noqa: F401
            # correlation counters: prefer explicitly named metrics for correlation rules
            from src.api.metrics_init import pipeline_stage_outcomes  # noqa: F401
        except Exception:
            pass
        try:
            from src.api.metrics_init import ensure_metrics as _e  # noqa: F401
        except Exception:
            pass
        try:
            # Create or fetch counters using the safe factory in metrics_init
            from src.api.metrics_init import _safe_counter, _safe_hist  # type: ignore
            _rule_hits_counter = _safe_counter('correlation_rule_hits_total', 'Correlation rule hits', ['rule'])
            _rule_score_hist = _safe_hist('correlation_rule_score_bucket', 'Correlation rule score buckets', ['rule','bucket'])
        except Exception:
            _rule_hits_counter = None
            _rule_score_hist = None


def inc_rule_fired(rule_name: str) -> None:
    """Increment the fired counter for a correlation rule.

    Prefer writing to the startup-created Prometheus Counter; otherwise
    increment an in-process counter used in tests and lightweight runs.
    """
    try:
        _ensure_local_handles()
    except Exception:
        pass
    try:
        if _rule_hits_counter is not None:
            try:
                _rule_hits_counter.labels(rule=rule_name).inc()
                return
            except Exception:
                pass
    except Exception:
        pass
    # Fallback: in-memory counter
    _counters[f'correlation_rule_fired_total{{rule="{rule_name}"}}'] += 1


def observe_rule_score(rule_name: str, score: float) -> None:
    """Record an observed score for a rule.

    We emit into a histogram-like helper with a `bucket` label (coarse buckets).
    """
    try:
        _ensure_local_handles()
    except Exception:
        pass
    try:
        bucket = int(min(max(score, 0.0), 0.99) * 10) / 10.0
        if _rule_score_hist is not None:
            try:
                _rule_score_hist.labels(rule=rule_name, bucket=str(bucket)).observe(float(score))
                return
            except Exception:
                pass
    except Exception:
        pass
    # Fallback recording
    b = int(min(max(score, 0.0), 0.99) * 10) / 10.0
    _score_buckets[rule_name][b] += 1


def get_metrics_snapshot() -> Dict[str, Any]:
    # If we have a registry, return that we are Prometheus-enabled. The
    # real /metrics endpoint will expose generate_latest(). For lightweight
    # consumption (tests), return a dict of in-memory counters when available.
    if METRICS_AVAILABLE and REGISTRY is not None:
        return {'prometheus_enabled': True}
    return {
        'counters': dict(_counters),
        'score_buckets': {k: dict(v) for k, v in _score_buckets.items()},
    }

