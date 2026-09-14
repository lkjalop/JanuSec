from __future__ import annotations
import json
import logging
import os
import uuid
from typing import Any, Dict, Optional

from .redis_helpers import get_redis_client

logger = logging.getLogger(__name__)


def _global_queue_key() -> str:
    return os.getenv('LLM_GLOBAL_QUEUE_KEY', 'llm:tasks')


def _priority_zset_key() -> str:
    return os.getenv('LLM_PRIORITY_ZSET', 'llm:priority')


def _per_assessment_queue_key(assessment_id: str) -> str:
    return f"llm:queue:{assessment_id}"


def enqueue_task(assessment_id: str, task: Dict[str, Any]) -> Optional[str]:
    """Persist a task into per-assessment queue and a global queue for workers.

    Returns the generated task id or None on failure.
    """
    client = get_redis_client()
    if client is None:
        logger.info('Redis not available; enqueue skipped')
        return None
    tid = task.get('task_id') or str(uuid.uuid4())
    task['task_id'] = tid
    task['assessment_id'] = assessment_id
    payload = json.dumps(task, default=str)
    try:
        # push to per-assessment list for visibility
        client.rpush(_per_assessment_queue_key(assessment_id), payload)
        # push to global worker queue (legacy poll-based workers)
        client.rpush(_global_queue_key(), payload)
        # compute a cheap heuristic priority score and add to priority zset
        try:
            score = _cheap_dread_score(task)
            client.zadd(_priority_zset_key(), {payload: float(score)})
        except Exception:
            # non-fatal: log and continue
            logger.exception('Failed adding task to priority zset')
        return tid
    except Exception:
        logger.exception('Failed enqueueing task for %s', assessment_id)
        return None


def dequeue_task(timeout: int = 5) -> Optional[Dict[str, Any]]:
    """Worker-facing blocking dequeue from global llm queue. Returns task dict or None."""
    client = get_redis_client()
    if client is None:
        return None
    try:
        res = client.blpop(_global_queue_key(), timeout=timeout)
        if not res:
            return None
        # res is (queue, payload)
        payload = res[1]
        if isinstance(payload, bytes):
            payload = payload.decode()
        task = json.loads(payload)
        return task
    except Exception:
        logger.exception('Failed to dequeue task')
        return None


def dequeue_batch(batch_size: int = 10, timeout: int = 5):
    """Dequeue up to batch_size tasks from the priority sorted set (best-effort).

    Falls back to popping from the global queue if priority zset is empty.
    Returns list[task_dict].
    """
    client = get_redis_client()
    if client is None:
        return []
    try:
        # Try to pop from priority zset using ZPOPMIN (Redis 5+)
        try:
            popped = client.zpopmin(_priority_zset_key(), count=batch_size)
        except AttributeError:
            # older redis-py may not expose zpopmin; emulate with pipeline
            popped = []
            try:
                # get top members
                members = client.zrange(_priority_zset_key(), 0, batch_size - 1)
                if members:
                    pipe = client.pipeline()
                    for m in members:
                        pipe.zrem(_priority_zset_key(), m)
                    pipe.execute()
                    popped = [(m, 0) for m in members]
            except Exception:
                popped = []
        tasks = []
        if popped:
            for member, score in popped:
                try:
                    if isinstance(member, bytes):
                        member = member.decode()
                    t = json.loads(member)
                    tasks.append(t)
                except Exception:
                    continue
            return tasks

        # fallback: drain up to batch_size items from the global list
        out = []
        for _ in range(batch_size):
            try:
                res = client.blpop(_global_queue_key(), timeout=timeout)
                if not res:
                    break
                payload = res[1]
                if isinstance(payload, bytes):
                    payload = payload.decode()
                out.append(json.loads(payload))
            except Exception:
                break
        return out
    except Exception:
        logger.exception('Failed dequeue_batch')
        return []


def _cheap_dread_score(task: Dict[str, Any]) -> float:
    """Compute a cheap heuristic DREAD-like score for prioritization.

    Higher score -> higher priority (use lower numeric value for zset if using zpopmin).
    We'll return a numeric score where smaller is higher priority.
    """
    try:
        payload = task.get('payload') or {}
        score = 100.0
        # simple heuristics: presence of 'malware', 'ransom', 'exe' increase priority
        text = json.dumps(payload).lower()
        if 'ransom' in text or 'encrypt' in text:
            score -= 40
        if 'malware' in text or '.exe' in text or 'elf' in text:
            score -= 30
        if 'phish' in text or 'spear' in text or 'bcc' in text:
            score -= 20
        # arrival time factor
        ts = task.get('ts') or task.get('created_ts') or 0
        try:
            score -= min(10, float(ts) % 10)
        except Exception:
            pass
        return max(1.0, score)
    except Exception:
        return 100.0


def peek_per_assessment_queue(assessment_id: str, limit: int = 10):
    client = get_redis_client()
    if client is None:
        return []
    try:
        items = client.lrange(_per_assessment_queue_key(assessment_id), 0, limit - 1)
        result = []
        for it in items:
            try:
                if isinstance(it, bytes):
                    it = it.decode()
                result.append(json.loads(it))
            except Exception:
                continue
        return result
    except Exception:
        logger.exception('Failed peeking per-assessment queue for %s', assessment_id)
        return []
