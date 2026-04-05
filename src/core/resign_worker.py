"""Worker to re-sign historical exported verification reports.

This module provides a small worker that can be scheduled as part of the
platform background tasks (or run separately) and consumes jobs enqueued
via `src.core.arc_redis_queue` (if Redis available) or an in-memory queue on
`app.state.arc_verify_queue` when run inside the API process.

Job payload shape (dict):
  {
    'type': 'resign_exports',
    'path_prefix': 'data/exports',  # directory containing exported JSON files
    'key_id': 'new-key-1',
    'batch_size': 50,
    'cursor': None
  }

The worker is restartable and uses cursor semantics: `cursor` is a filename
marker; files earlier than cursor are skipped. The worker will write new
files alongside the originals with suffix `.resigned.<key_id>.json`.
"""
from __future__ import annotations

import os
import json
import time
import base64
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

try:
    from src.core.arc_redis_queue import pop_job, ack_job, enqueue_job, get_redis_client
except Exception:
    pop_job = None
    ack_job = None
    enqueue_job = None
    get_redis_client = None


def _update_status(job_id: str, data: dict):
    """Update job status either in Redis or filesystem status file."""
    try:
        rc = get_redis_client()
        if rc is not None:
            rc.hset('resign:status', job_id, json.dumps(data))
            return
    except Exception:
        pass
    # fs fallback
    d = os.path.join('data', 'resign_jobs')
    os.makedirs(d, exist_ok=True)
    status_fp = os.path.join(d, f"{job_id}.status.json")
    try:
        with open(status_fp, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(data))
    except Exception:
        pass


def _list_export_files(prefix: str):
    if not os.path.isdir(prefix):
        return []
    files = [os.path.join(prefix, f) for f in os.listdir(prefix) if f.endswith('.json')]
    files.sort()
    return files


def _process_single_file(path: str, key_id: str) -> Optional[str]:
    """Re-sign a single exported report with `key_id`. Returns new path or None."""
    try:
        from src.core.keystore import resolve_key_plaintext
    except Exception:
        logger.exception('keystore import failed')
        return None
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            obj = json.load(fh)
    except Exception:
        logger.exception('failed reading exported file %s', path)
        return None
    secret = resolve_key_plaintext(key_id)
    if not secret:
        logger.error('no plaintext available for key_id=%s', key_id)
        return None
    try:
        # Recompute signature using the existing export_report_json verify logic.
        # We'll use scripts.verify_approval_audit.export_report_json to canonicalize
        # and sign the payload. To avoid circular import, perform local signing.
        body = dict(obj)
        # remove existing signature if present
        body.pop('_signature', None)
        body['key_id'] = key_id
        payload = json.dumps(body, sort_keys=True).encode('utf-8')
        import hmac, hashlib
        sig = hmac.new(secret.encode('utf-8'), payload, hashlib.sha256).hexdigest()
        body['_signature'] = sig
        new_name = path + f'.resigned.{key_id}.json'
        with open(new_name, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(body, indent=2))
        return new_name
    except Exception:
        logger.exception('failed signing %s', path)
        return None


def _process_job(job: Dict[str, Any]):
    typ = job.get('type')
    if typ != 'resign_exports':
        logger.debug('unsupported job type %s', typ)
        return False
    prefix = job.get('path_prefix') or os.getenv('APPROVAL_EXPORTS_DIR', 'data/approvals/exports')
    key_id = job.get('key_id')
    batch = int(job.get('batch_size') or 50)
    cursor = job.get('cursor')
    files = _list_export_files(prefix)
    start = 0
    if cursor:
        try:
            start = files.index(cursor) + 1
        except Exception:
            start = 0
    processed = 0
    next_cursor = None
    job_id = job.get('job_id') or f"job-{int(time.time())}-{os.urandom(4).hex()}"
    # initialize status
    _update_status(job_id, {'state': 'running', 'processed': 0, 'created_ts': int(time.time())})
    for p in files[start:]:
        if processed >= batch:
            next_cursor = p
            break
        # idempotency: skip if target resigned file exists
        target = p + f'.resigned.{key_id}.json'
        if os.path.exists(target):
            processed += 1
            _update_status(job_id, {'state': 'running', 'processed': processed})
            continue
        res = _process_single_file(p, key_id)
        if res:
            processed += 1
            _update_status(job_id, {'state': 'running', 'processed': processed})
    # If there are still files, schedule another job with updated cursor
    remaining = len(files) - (start + processed)
    if remaining > 0 and next_cursor:
        # schedule follow-up job
        follow = dict(job)
        follow['cursor'] = next_cursor
        try:
            if enqueue_job:
                enqueue_job(follow)
            else:
                # best-effort: write follow job to a local queue file (noop for now)
                logger.info('would enqueue follow-up job %s', follow)
        except Exception:
            logger.exception('failed to enqueue follow-up')
    logger.info('processed=%d remaining=%d', processed, max(0, remaining))
    # finalize status
    _update_status(job_id, {'state': 'completed', 'processed': processed, 'remaining': max(0, remaining)})
    return True


def run_once_from_redis(timeout: int = 5):
    """Pop a job from redis queue and process it (blocking up to timeout seconds)."""
    if pop_job is None:
        return False
    popped = pop_job(timeout=timeout)
    if not popped:
        return False
    job, payload_str = popped
    try:
        ok = _process_job(job)
        if ok and ack_job:
            try:
                ack_job(payload_str)
            except Exception:
                pass
        return ok
    except Exception:
        logger.exception('processing job failed')
        return False


def run_in_process_queue(app, max_iter: int = 100):
    """Run job processor against the application's in-memory arc_verify_queue."""
    q = getattr(app.state, 'arc_verify_queue', None)
    if q is None:
        logger.error('no in-process arc_verify_queue available')
        return
    it = 0
    while it < max_iter:
        try:
            job = app.loop.run_until_complete(q.get())
        except Exception:
            break
        try:
            _process_job(job)
        except Exception:
            logger.exception('job failed')
        it += 1


__all__ = ['run_once_from_redis', 'run_in_process_queue', '_process_job']
