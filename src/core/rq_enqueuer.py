from __future__ import annotations
import os
import json
import logging
from redis import Redis
from rq import Queue

from .redis_llm_queue import enqueue_task

logger = logging.getLogger(__name__)


def get_rq_connection():
    redis_url = os.getenv('REDIS_URL')
    return Redis.from_url(redis_url) if redis_url else Redis()


def enqueue_rq_job(assessment_id: str, task: dict, queue_name: str = 'default') -> bool:
    """Enqueue a job both into the Redis-backed RQ queue and the per-assessment list.

    Returns True on success.
    """
    # persist to per-assessment visibility queue as well
    try:
        enqueue_task(assessment_id, task)
    except Exception:
        logger.exception('Failed enqueue_task fallback')
    try:
        conn = get_rq_connection()
        q = Queue(queue_name, connection=conn)
        # Use the function path that workers import: src.workers.llm_worker.process_task
        q.enqueue('src.workers.llm_worker.process_task', task)
        return True
    except Exception:
        logger.exception('Failed enqueueing RQ job')
        return False
