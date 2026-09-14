"""CyberStash webhook receiver.

Implements a lightweight HMAC+timestamp verification, replay protection and
background enqueueing of incoming alerts. Mirrors the repository's existing
XDR webhook semantics but kept intentionally small and self-contained for
demo/testing.
"""
from __future__ import annotations

import hmac
import hashlib
import json
import os
import time
import uuid
from collections import deque
from typing import Any, Deque, Set, Tuple
from core.replay_cache import replay_add, replay_exists
from core.writeback_dlq import enqueue as dlq_enqueue

from fastapi import APIRouter, Request, BackgroundTasks, HTTPException

router = APIRouter(tags=["CyberStash"])

# Config
_CS_SECRET_ENV = os.getenv('CYBERSTASH_WEBHOOK_SECRET', None)
_CS_REPLAY_WINDOW = int(os.getenv('CYBERSTASH_WEBHOOK_TS_SKEW', '300'))
_CS_MAX_BODY = int(os.getenv('CYBERSTASH_WEBHOOK_MAX_BYTES', '262144'))

# Simple replay cache
_CS_REPLAY_CACHE: Deque[Tuple[str, str]] = deque(maxlen=5000)  # (timestamp, signature)
_CS_REPLAY_SET: Set[Tuple[str, str]] = set()


def _make_sig(secret: str, body: bytes, ts: int) -> str:
    mac = hmac.new(secret.encode('utf-8'), msg=str(ts).encode('utf-8') + b'.' + body, digestmod=hashlib.sha256)
    return mac.hexdigest()


def _timestamp_fresh(ts: str) -> bool:
    try:
        t = int(ts)
    except Exception:
        return False
    now = int(time.time())
    return abs(now - t) <= _CS_REPLAY_WINDOW


def _replay_check(timestamp: str, signature: str) -> bool:
    key = (timestamp, signature)
    if key in _CS_REPLAY_SET:
        return False
    # prune by timestamp window
    cutoff = int(time.time()) - _CS_REPLAY_WINDOW
    while _CS_REPLAY_CACHE and int(_CS_REPLAY_CACHE[0][0]) < cutoff:
        old = _CS_REPLAY_CACHE.popleft()
        _CS_REPLAY_SET.discard(old)
    _CS_REPLAY_CACHE.append(key)
    _CS_REPLAY_SET.add(key)
    return True


async def _process_alert(payload: dict[str, Any], task_id: str) -> None:
    """Background processing placeholder: normalize + publish decision.

    This is intentionally minimal for tests/demo. In production you'd map
    to the platform decision schema, enrich and publish to the decisions
    stream / SOAR pipeline.
    """
    try:
        # best-effort publish to decisions_stream if available
        from .decisions_stream import publish_decision
        event_id = payload.get('id') or f"cyberstash-{int(time.time()*1000)}"
        summary = {
            'event_id': event_id,
            'verdict': 'OBSERVE',
            'confidence': 0.0,
            'factors': ['cyberstash:webhook'],
            'integrator_id': 'cyberstash',
            'ts': time.time(),
            'task_id': task_id,
            'raw': payload,
        }
        await publish_decision(summary)
    except Exception:
        # swallow errors in background worker for demo safety
        pass


@router.post('/api/v1/integrations/cyberstash/webhook')
async def cyberstash_webhook(request: Request, background_tasks: BackgroundTasks):
    """Receive CyberStash webhook with HMAC+timestamp verification.

    Headers expected:
      - X-Timestamp: unix seconds
      - X-Signature: hex HMAC-SHA256 over `timestamp + '.' + raw_body`
    """
    # get headers
    signature = request.headers.get('X-Signature') or request.headers.get('x-signature')
    timestamp = request.headers.get('X-Timestamp') or request.headers.get('x-timestamp')
    if not (signature and timestamp):
        raise HTTPException(status_code=400, detail='missing_headers')
    if not _timestamp_fresh(timestamp):
        raise HTTPException(status_code=401, detail='stale_timestamp')
    body = await request.body()
    if len(body) > _CS_MAX_BODY:
        raise HTTPException(status_code=413, detail='payload_too_large')
    # secret must be configured (in env or vault in prod)
    secret = _CS_SECRET_ENV or os.getenv('CYBERSTASH_WEBHOOK_SECRET')
    if not secret:
        raise HTTPException(status_code=403, detail='missing_server_secret')
    # replay check (use Redis-backed cache if configured)
    replay_key = f"cyberstash:{timestamp}:{signature}"
    if replay_exists(replay_key):
        raise HTTPException(status_code=409, detail='replay_detected')
    # mark as seen
    replay_add(replay_key)
    # verify signature
    expected = _make_sig(secret, body, int(timestamp))
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail='bad_signature')
    # parse body
    try:
        payload = json.loads(body.decode('utf-8'))
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    task_id = str(uuid.uuid4())
    # background processing
    try:
        background_tasks.add_task(_process_alert, payload, task_id)
    except Exception:
        # If background scheduling fails, enqueue for retry in DLQ
        dlq_enqueue({'task_id': task_id, 'payload': payload})
    return {'accepted': True, 'task_id': task_id, 'queued': True}


__all__ = ['router']
