import asyncio
import json
import time
from typing import Any

from .dispatch_outbox import get_pending, mark_attempt, mark_done, compute_backoff, get_by_id

from src.api.pull_endpoints import identity_pull, edr_process_tree_pull, dns_lookup_pull


async def _dispatch_row(row: dict, app) -> bool:
    # returns True on success, False on retryable failure
    did = row.get('id')
    endpoint = row.get('endpoint') or ''
    payload = {}
    try:
        payload = json.loads(row.get('payload') or '{}').get('payload', {})
    except Exception:
        payload = {}
    attempts = int(row.get('attempts') or 0)
    try:
        # choose handler
        if 'identity' in endpoint.lower():
            res = await identity_pull(payload, None)
        elif 'edr' in endpoint.lower() or 'process_tree' in endpoint.lower():
            res = await edr_process_tree_pull(payload, None)
        elif 'dns' in endpoint.lower():
            res = await dns_lookup_pull(payload, None)
        else:
            # unsupported endpoint - mark as failed permanently
            mark_attempt(did, attempts + 1, 'unsupported_endpoint', status='failed')
            return True
        # success
        mark_done(did)
        return True
    except Exception as e:
        attempts = attempts + 1
        # compute backoff but keep the row pending
        backoff = compute_backoff(attempts, base=1.0, cap=300.0, jitter=0.25)
        mark_attempt(did, attempts, str(e), status='pending')
        # schedule next run after backoff by sleeping here
        await asyncio.sleep(backoff)
        return False


async def outbox_processor_task(app, loop_delay: float = 1.0, batch: int = 10):
    """Async background task that polls the outbox and processes entries."""
    while True:
        try:
            rows = get_pending(limit=batch)
            if not rows:
                await asyncio.sleep(loop_delay)
                continue
            for row in rows:
                # For each row, attempt dispatch. If returns False, we'll continue and the
                # backoff sleep already scheduled in _dispatch_row before next loop iteration.
                try:
                    await _dispatch_row(row, app)
                except Exception:
                    # swallow; continue to next row
                    continue
        except Exception:
            await asyncio.sleep(loop_delay)
