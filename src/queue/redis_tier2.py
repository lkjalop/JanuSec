"""Optional Redis-backed Tier2 job queue with graceful fallback to filesystem persistence.

This module attempts to import `redis` and exposes a small producer/consumer API:
- init(redis_url)
- enqueue(job_id, job_payload)
- dequeue(block=True, timeout=1)
- ack(job_id)
- stop()

If Redis is unavailable, functions raise ImportError so callers can fall back.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

try:
    import redis
except Exception:
    redis = None

_redis_client = None
_QUEUE_KEY = 'tier2:jobs'
_INFLIGHT_KEY = 'tier2:inflight'
_JOB_KEY_PREFIX = 'tier2:job:'
_STREAM_KEY = 'tier2:stream'
_USE_STREAMS = False
try:
    import os as _os
    _USE_STREAMS = (_os.getenv('TIER2_USE_STREAMS','0').lower() in {'1','true','yes'})
except Exception:
    _USE_STREAMS = False


def init(redis_url: str) -> None:
    global _redis_client
    if redis is None:
        raise ImportError('redis package not installed')
    _redis_client = redis.from_url(redis_url)


def enqueue(job_id: str, job_payload: Dict[str, Any]) -> None:
    if _redis_client is None:
        raise RuntimeError('redis client not initialized')
    # Persist job state under a dedicated key and mark queued
    try:
        _redis_client.set(_JOB_KEY_PREFIX + job_id, json.dumps({**job_payload, 'status': 'queued', 'cancel_requested': False}))
    except Exception:
        pass
    # If stream mode enabled and supported, XADD to stream for consumer groups
    if _USE_STREAMS:
        try:
            # payload stored as JSON string under field 'j'
            _redis_client.xadd(_STREAM_KEY, {'j': json.dumps({'job_id': job_id})})
            return
        except Exception:
            # fall back to list if streams not available
            pass
    _redis_client.rpush(_QUEUE_KEY, json.dumps({'job_id': job_id}))


def dequeue(block: bool = True, timeout: int = 1) -> Optional[Dict[str, Any]]:
    if _redis_client is None:
        raise RuntimeError('redis client not initialized')
    if block:
        item = _redis_client.blpop(_QUEUE_KEY, timeout=timeout)
        if not item:
            return None
        _, data = item
    else:
        data = _redis_client.lpop(_QUEUE_KEY)
        if not data:
            return None
    try:
        obj_ref = json.loads(data)
        job_id = obj_ref.get('job_id')
        # load job payload from dedicated key
        try:
            raw = _redis_client.get(_JOB_KEY_PREFIX + job_id)
            if raw:
                job = json.loads(raw)
            else:
                job = {'job_id': job_id, 'status': 'queued', 'rows': []}
        except Exception:
            job = {'job_id': job_id, 'status': 'queued', 'rows': []}
        # mark inflight for visibility
        try:
            _redis_client.hset(_INFLIGHT_KEY, job_id, json.dumps(job))
        except Exception:
            pass
        return {'job_id': job_id, 'payload': job}
    except Exception:
        return None


def enqueue_stream_only(job_id: str, job_payload: Dict[str, Any]) -> None:
    """Explicit stream enqueue helper for tests; raises if streams not enabled."""
    if not _USE_STREAMS or _redis_client is None:
        raise RuntimeError('streams_not_enabled')
    try:
        _redis_client.set(_JOB_KEY_PREFIX + job_id, json.dumps({**job_payload, 'status': 'queued', 'cancel_requested': False}))
        _redis_client.xadd(_STREAM_KEY, {'j': json.dumps({'job_id': job_id})})
    except Exception as exc:
        raise


def ack(job_id: str) -> None:
    if _redis_client is None:
        raise RuntimeError('redis client not initialized')
    try:
        _redis_client.hdel(_INFLIGHT_KEY, job_id)
        # remove persisted job payload
        try:
            _redis_client.delete(_JOB_KEY_PREFIX + job_id)
        except Exception:
            pass
    except Exception:
        pass


def stop() -> None:
    # No-op for now; consumers can simply exit their loops
    return
