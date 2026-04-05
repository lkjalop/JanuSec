"""Test helper: standalone Redis consumer loop for Tier2 jobs.

This consumer pops jobs from Redis via `redis_tier2.dequeue()` and processes them
using the existing `_generate_tier2_summary` function by importing the endpoints
module. It updates the persisted job file and calls `redis_tier2.ack()` when done.

This module is intentionally lightweight and used by integration tests to simulate
multi-worker processing.
"""
from __future__ import annotations

import time
import logging
from typing import Any

logger = logging.getLogger(__name__)
try:
    from src.queue.redis_tier2 import dequeue, ack
    from src.api.insights_endpoints import _generate_tier2_summary, _persist_tier2_job, TIER2_JOBS
except Exception as exc:
    logger.exception('Redis consumer helper unavailable: %s', exc)
    raise


def consumer_loop(run_seconds: int = 5):
    end = time.time() + run_seconds
    while time.time() < end:
        item = dequeue(block=True, timeout=1)
        if not item:
            continue
        try:
            job_id = item.get('job_id')
            job = item.get('payload') or {}
            # register job locally for visibility
            TIER2_JOBS[job_id] = job
            job['status'] = 'running'
            _persist_tier2_job(job_id)
            results = []
            rows = job.get('rows') or []
            for r in rows:
                # Check cancel flag persisted in TIER2_JOBS or redis-backed store
                if TIER2_JOBS.get(job_id, {}).get('cancel_requested'):
                    job['status'] = 'cancelled'
                    TIER2_JOBS[job_id] = job
                    _persist_tier2_job(job_id)
                    break
                try:
                    text, model, pl = _generate_tier2_summary(r.get('raw') if isinstance(r, dict) else r, job.get('pipeline_context') or {})
                    results.append({'row_index': r.get('row_index'), 'model': model, 'payload': pl})
                except Exception as e:
                    results.append({'row_index': r.get('row_index'), 'error': str(e)})
            if job.get('status') != 'cancelled':
                job['results'] = results
                job['status'] = 'completed'
                TIER2_JOBS[job_id] = job
                _persist_tier2_job(job_id)
            try:
                ack(job_id)
            except Exception:
                pass
        except Exception:
            logger.exception('Failed to process redis job')