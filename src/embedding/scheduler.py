from __future__ import annotations
"""Adaptive Embedding Scheduler

Periodically refresh embeddings for active factors & tokens without
blocking request paths.

Candidates:
 - Recent decision `factors` values (up to EMBED_SCHED_DECISION_SCAN)
 - `file_hash_factors` keys (hash tokens) from runtime
 - `beacon_scores` keys (beacon candidate ids)

Environment vars:
 EMBED_SCHED_INTERVAL_SECONDS  (default 300; 0 disables)
 EMBED_SCHED_BATCH_SIZE        (default 75)
 EMBED_SCHED_MAX_FACTORS       (default 500)
 EMBED_SCHED_DECISION_SCAN     (default 400)  number of recent decisions to scan
 EMBED_SCHED_LOG_EVERY         (default 10)   log every N runs
 ENABLE_EMBEDDING_SCHEDULER    (1/0)          explicit enable toggle (default on if interval>0)

Metrics (best-effort; created via safe wrappers):
 embedding_scheduler_runs_total{status}
 embedding_scheduler_factors_total
 embedding_scheduler_duration_seconds
"""
import os, time, random, logging
from typing import Iterable

logger = logging.getLogger(__name__)

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)) or default)
    except Exception:
        return default

def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)) or default)
    except Exception:
        return default

def _collect_factors(runtime, decision_cache, max_scan: int) -> set[str]:
    factors: set[str] = set()
    # Scan recent decisions
    try:
        if decision_cache is not None:
            # decision_cache may not preserve order; sample keys
            keys = list(getattr(decision_cache, 'keys', lambda: [])())
            if keys:
                # Take last N keys if orderable else random sample
                try:
                    keys_sorted = keys[-max_scan:]
                except Exception:
                    keys_sorted = random.sample(keys, min(len(keys), max_scan))
                for k in keys_sorted:
                    try:
                        rec = decision_cache.get(k)  # dict-like
                        if isinstance(rec, dict):
                            for f in rec.get('factors', []) or []:
                                if isinstance(f, str) and f:
                                    factors.add(f)
                    except Exception:
                        pass
    except Exception:
        pass
    # file hash tokens
    try:
        for sha in list(getattr(runtime, 'file_hash_factors', {}).keys())[:max_scan]:
            if isinstance(sha, str) and sha:
                factors.add(f'sha256:{sha[:32]}')
    except Exception:
        pass
    # beacon score keys
    try:
        for bid in list(getattr(runtime, 'beacon_scores', {}).keys())[:max_scan]:
            if isinstance(bid, str) and bid:
                factors.add(f'beacon:{bid}')
    except Exception:
        pass
    return factors

async def embedding_scheduler_loop(app) -> None:  # pragma: no cover (background loop)
    interval = _env_int('EMBED_SCHED_INTERVAL_SECONDS', 300)
    if interval <= 0:
        logger.info('Embedding scheduler disabled (interval=%s)', interval)
        return
    batch_size = _env_int('EMBED_SCHED_BATCH_SIZE', 75)
    max_factors = _env_int('EMBED_SCHED_MAX_FACTORS', 500)
    decision_scan = _env_int('EMBED_SCHED_DECISION_SCAN', 400)
    log_every = _env_int('EMBED_SCHED_LOG_EVERY', 10)
    runs = 0
    # Metrics setup
    try:
        from src.api.metrics_init import ensure_metrics
        ensure_metrics()
        from src.api.metrics_init import _safe_counter, _safe_gauge
        runs_counter = _safe_counter('embedding_scheduler_runs_total','Embedding scheduler runs',['status'])
        factors_counter = _safe_counter('embedding_scheduler_factors_total','Total factor embeddings produced')
        duration_gauge = _safe_gauge('embedding_scheduler_duration_seconds','Last embedding scheduler run duration seconds')
    except Exception:
        class _Dummy:
            def labels(self,*a,**k): return self
            def inc(self,*a,**k): pass
            def set(self,*a,**k): pass
        runs_counter = factors_counter = duration_gauge = _Dummy()
    from src.api.runtime_state import get_server_runtime_state, DECISION_CACHE
    from .service import get_embedding_service
    service = get_embedding_service()
    import asyncio
    while True:
        start = time.time(); status = 'ok'
        try:
            runtime = get_server_runtime_state(app)
            all_factors = _collect_factors(runtime, DECISION_CACHE, decision_scan)
            if not all_factors:
                status = 'empty'
            else:
                # Limit total factors retained
                factor_list = list(all_factors)
                random.shuffle(factor_list)
                factor_list = factor_list[:max_factors]
                # Sample for this run
                sample = factor_list[:batch_size]
                if sample:
                    vectors = service.embed_texts(sample)
                    try:
                        store = getattr(runtime, 'factor_embeddings', None)
                        if store is None:
                            runtime.factor_embeddings = {}
                            store = runtime.factor_embeddings
                        for f, v in zip(sample, vectors):
                            store[f] = v
                        factors_counter.inc(len(sample))
                    except Exception:
                        pass
        except Exception as e:
            status = 'error'
            logger.warning('embedding_scheduler_loop error: %s', e)
        runs += 1
        try:
            runs_counter.labels(status=status).inc()
            duration_gauge.set(time.time() - start)
            if runs % max(1, log_every) == 0:
                logger.info('Embedding scheduler run #%d status=%s stored=%d', runs, status, len(getattr(runtime,'factor_embeddings',{})))
        except Exception:
            pass
        await asyncio.sleep(interval)

def register_embedding_scheduler(app) -> None:
    try:
        enabled = os.getenv('ENABLE_EMBEDDING_SCHEDULER')
        interval = _env_int('EMBED_SCHED_INTERVAL_SECONDS', 300)
        # Enabled if interval>0 and (flag unset or truthy)
        if interval > 0 and (enabled is None or enabled.lower() in {'1','true','yes'}):
            import asyncio
            app.add_event_handler('startup', lambda: asyncio.create_task(embedding_scheduler_loop(app)))
            logger.info('Registered embedding scheduler (interval=%s)', interval)
        else:
            logger.info('Embedding scheduler not registered (interval=%s enabled_flag=%s)', interval, enabled)
    except Exception as e:
        logger.warning('Failed to register embedding scheduler: %s', e)

__all__ = ['register_embedding_scheduler']