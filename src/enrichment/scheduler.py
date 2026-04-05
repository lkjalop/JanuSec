"""Enrichment scheduler: manage periodic refresh of EPSS/KEV with persistence.

Stores a simple job registry in data/enrichment_jobs.json with next_run and backoff.
"""
from __future__ import annotations
import asyncio
import json
import os
import time
import random
from pathlib import Path
import logging
from typing import Dict, Any
try:
    from prometheus_client import Gauge, Counter
except Exception:
    Gauge = None
    Counter = None

logger = logging.getLogger(__name__)
JOB_FILE = Path('data') / 'enrichment_jobs.json'


def _load_jobs() -> Dict[str, Any]:
    try:
        JOB_FILE.parent.mkdir(parents=True, exist_ok=True)
        if JOB_FILE.exists():
            return json.loads(JOB_FILE.read_text(encoding='utf-8') or '{}')
    except Exception:
        pass
    return {}


def _save_jobs(jobs: Dict[str, Any]) -> None:
    try:
        JOB_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = JOB_FILE.with_suffix('.tmp')
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump(jobs, fh)
        tmp.replace(JOB_FILE)
    except Exception:
        pass


def schedule_refresh(item_key: str, interval: int = 3600):
    # If Redis-backed scheduler is enabled prefer that path
    if os.getenv('ENABLE_REDIS_SCHEDULER','0').lower() in {'1','true','yes'}:
        try:
            import asyncio
            from src.enrichment.redis_scheduler import get_global_scheduler
            async def _delegate():
                sched = await get_global_scheduler()
                if sched is not None:
                    await sched.schedule(item_key, {'key': item_key}, interval=interval)
                    return True
                return False
            try:
                asyncio.run(_delegate())
                return
            except Exception:
                pass
        except Exception:
            pass
    jobs = _load_jobs()
    now = int(time.time())
    if item_key not in jobs:
        jobs[item_key] = {'next_run': now + random.randint(0, min(60, interval)), 'interval': interval, 'backoff': 0}
    else:
        jobs[item_key].setdefault('interval', interval)
        jobs[item_key].setdefault('backoff', 0)
        jobs[item_key]['next_run'] = now + random.randint(0, min(60, interval))
    _save_jobs(jobs)


def _mark_success(item_key: str):
    jobs = _load_jobs()
    if item_key in jobs:
        jobs[item_key]['backoff'] = 0
        jobs[item_key]['next_run'] = int(time.time()) + jobs[item_key].get('interval', 3600)
        _save_jobs(jobs)


def _mark_failure(item_key: str):
    jobs = _load_jobs()
    if item_key in jobs:
        b = jobs[item_key].get('backoff', 0) + 1
        back = min(6, b)
        jitter = random.randint(1, 30)
        jobs[item_key]['backoff'] = back
        jobs[item_key]['next_run'] = int(time.time()) + (2 ** back) + jitter
        _save_jobs(jobs)


    # Simple metrics for file-backed scheduler
    _JOB_GAUGE = Gauge('enrich_jobs_count', 'Number of file-backed enrichment jobs') if Gauge else None
    _ERR_COUNTER = Counter('enrich_scheduler_errors_total', 'Scheduler errors (file-backed)') if Counter else None


async def _scheduler_loop():
    # Poll jobs file and execute refreshes; uses clients.fetch_epss_for_hash and fetch_kev_for_cve
    from src.enrichment.clients import fetch_epss_for_hash, fetch_kev_for_cve
    while True:
        try:
            jobs = _load_jobs()
            try:
                if _JOB_GAUGE is not None:
                    _JOB_GAUGE.set(len(jobs))
            except Exception:
                pass
            now = int(time.time())
            keys = list(jobs.keys())
            for k in keys:
                try:
                    item = jobs.get(k, {})
                    if item.get('next_run', 0) <= now:
                        # item key may be 'hash:<sha>' or 'cve:CVE-...'
                        if k.startswith('hash:'):
                            sha = k.split(':',1)[1]
                            res = await fetch_epss_for_hash(sha)
                            if res:
                                _mark_success(k)
                            else:
                                _mark_failure(k)
                        elif k.startswith('cve:'):
                            cve = k.split(':',1)[1]
                            res = await fetch_kev_for_cve(cve)
                            if res:
                                _mark_success(k)
                            else:
                                _mark_failure(k)
                except Exception:
                    logger.exception('job execution failed for %s', k)
            await asyncio.sleep(5)
        except Exception:
            logger.exception('scheduler loop error')
            try:
                if _ERR_COUNTER is not None:
                    _ERR_COUNTER.inc()
            except Exception:
                pass
            await asyncio.sleep(5)


def register_scheduler(app):
    try:
        if os.getenv('ENABLE_ENRICHMENT_SCHEDULER','0').lower() in {'1','true','yes'}:
            app.add_event_handler('startup', lambda: asyncio.create_task(_scheduler_loop()))
    except Exception:
        logger.exception('Failed to register enrichment scheduler')
