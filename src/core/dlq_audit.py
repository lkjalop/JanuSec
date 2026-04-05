from __future__ import annotations

import logging
import time
import json
from typing import Any

logger = logging.getLogger(__name__)


def record_requeue_audit(dlq_id: int, user: dict | None, original_payload: dict, new_payload: dict) -> None:
    """Best-effort audit record.

    Attempts to write into a DB audit table `dlq_admin_audit` if available; otherwise
    falls back to logging the audit entry.
    """
    entry = {
        'dlq_id': dlq_id,
        'user': user or {'system': True},
        'ts': time.time(),
        'original': original_payload,
        'new': new_payload,
    }
    try:
        # Try DB path first
        try:
            from db.adapter import execute as db_execute
            sql = 'INSERT INTO dlq_admin_audit (dlq_id, user_info, original_payload, new_payload, created_at) VALUES ($1,$2,$3,$4,NOW())'
            # execute may be async or sync depending on adapter, but this helper is sync; attempt best-effort
            maybe = db_execute(sql, dlq_id, json.dumps(entry.get('user')), json.dumps(original_payload), json.dumps(new_payload))
            # if coroutine, schedule in event loop if available
            import asyncio
            if asyncio.iscoroutine(maybe):
                loop = asyncio.get_event_loop()
                loop.create_task(maybe)
            return
        except Exception:
            pass
    except Exception:
        pass
    # fallback to logger
    try:
        logger.info('DLQ_AUDIT: %s', json.dumps(entry, default=str))
    except Exception:
        logger.info('DLQ_AUDIT: dlq_id=%s user=%s', dlq_id, (user or {}))
