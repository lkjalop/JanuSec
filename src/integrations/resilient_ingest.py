from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List

from ._backoff import retry_with_backoff
try:
    from src.core.durable_dlq import enqueue as dlq_enqueue
except Exception:
    try:
        from src.core.writeback_dlq import enqueue as dlq_enqueue
    except Exception:
        from core.writeback_dlq import enqueue as dlq_enqueue

logger = logging.getLogger(__name__)


def resilient_post(post_fn: Callable[[], Any], payload_for_dlq: Dict[str, Any], attempts: int = 3) -> Any:
    """Call `post_fn` with retry/backoff; on final failure write `payload_for_dlq` to DLQ."""
    try:
        return retry_with_backoff(post_fn, attempts=attempts)
    except Exception as e:
        try:
            logger.exception('Resilient post failed, enqueuing to DLQ')
            dlq_enqueue(payload_for_dlq)
        except Exception:
            logger.exception('Failed to write payload to DLQ')
        raise


def build_post_payload(base_url: str, api_key: str, tenant_id: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        'base_url': base_url,
        'api_key': api_key,
        'tenant_id': tenant_id,
        'events_count': len(events),
        'events_sample': events[:5],
    }
