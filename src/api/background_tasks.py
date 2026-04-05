from __future__ import annotations

import asyncio
import os
import time
import json
from typing import Any

from fastapi import FastAPI

from src.core.monitoring.ingestion_anomaly import IngestionAnomalyDetector
from src.core.cache.explanation_cache import ExplanationCache
from src.core.cache.explain_generator import compute_explain
from src.api.metrics_init import _safe_counter, _safe_hist


def register_background_tasks(app: FastAPI) -> None:
    """Register background loops via app.add_event_handler('startup', ...).

    Runs only in non-test/lite modes when app starts.
    """
    try:
        if os.getenv('PLATFORM_LITE_INIT','').lower() in {'1','true','yes'} or os.getenv('FAST_TEST_MODE','').lower() in {'1','true','yes'}:
            return
    except Exception:
        pass

    detector = IngestionAnomalyDetector()
    cache = ExplanationCache()

    explain_precompute_counter = _safe_counter('explain_precompute_runs_total', 'Explain precompute runs')
    explain_cache_hit = _safe_counter('explain_cache_hits_total', 'Explain cache hits')
    explain_cache_miss = _safe_counter('explain_cache_misses_total', 'Explain cache misses')
    explain_precompute_latency = _safe_hist('explain_precompute_latency_seconds', 'Explain precompute latency seconds')

    async def _ingest_gap_loop():
        poll = int(os.getenv('INGESTION_GAP_POLL_SEC', '60') or 60)
        while True:
            try:
                detector.detect_gaps()
            except Exception:
                pass
            await asyncio.sleep(max(10, poll))

    async def _explain_precompute_loop():
        sess_dir = os.getenv('SESSION_PERSIST_DIR', 'data/sessions')
        interval = int(os.getenv('EXPLAIN_PRECOMPUTE_INTERVAL_SEC', '300') or 300)
        while True:
            try:
                now = time.time()
                # scan for incident files
                if os.path.isdir(sess_dir):
                    for fn in os.listdir(sess_dir):
                        try:
                            if not (fn.startswith('incident_') and fn.endswith('.json')):
                                continue
                            p = os.path.join(sess_dir, fn)
                            with open(p, 'r', encoding='utf-8') as fh:
                                data = json.load(fh) or {}
                            fp = data.get('fingerprint') or data.get('id') or fn
                            key = f"incident:{fp}"
                            if cache.get(key):
                                explain_cache_hit.labels().inc(1)
                                continue
                            # compute explanation via generator
                            explain_precompute_counter.labels().inc(1)
                            started = time.time()
                            payload = await compute_explain(fp, data.get('payload') or {})
                            duration = time.time() - started
                            cache.set(key, payload, ttl=int(os.getenv('EXPLAIN_CACHE_TTL','3600')),
                                      meta={'generator': 'precompute_loop', 'generated_at': now, 'duration_s': duration})
                        except Exception:
                            explain_cache_miss.labels().inc(1)
                            continue
            except Exception:
                pass
            await asyncio.sleep(max(30, interval))

    def _start_tasks():
        try:
            asyncio.create_task(_ingest_gap_loop())
            asyncio.create_task(_explain_precompute_loop())
            # start resign worker poll loop if redis queue available or local jobs exist
            try:
                from src.core.resign_worker import run_once_from_redis
                from src.core.arc_redis_queue import get_redis_client
                rc = get_redis_client()
                if rc is not None:
                    async def _resign_redis_loop():
                        while True:
                            try:
                                # blocking pop with short timeout
                                run_once_from_redis(timeout=5)
                            except Exception:
                                pass
                            await asyncio.sleep(0.1)
                    asyncio.create_task(_resign_redis_loop())
            except Exception:
                pass
            # local resign job processor: look for jobs in data/resign_jobs and run them
            try:
                import pathlib
                from src.core.resign_worker import _process_job
                async def _resign_local_loop():
                    jobs_dir = pathlib.Path('data') / 'resign_jobs'
                    while True:
                        try:
                            if jobs_dir.exists():
                                for p in sorted(jobs_dir.iterdir()):
                                    try:
                                        if p.suffix != '.json':
                                            continue
                                        with open(p, 'r', encoding='utf-8') as fh:
                                            job = json.load(fh)
                                        _process_job(job)
                                        try:
                                            p.unlink()
                                        except Exception:
                                            pass
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                        await asyncio.sleep(10)
                asyncio.create_task(_resign_local_loop())
            except Exception:
                pass
        except Exception:
            pass

    app.add_event_handler('startup', _start_tasks)


__all__ = ['register_background_tasks']
