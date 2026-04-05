from __future__ import annotations

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


def check_tier3_usage(get_tier3_usage_fn) -> Optional[dict]:
    """Check Tier3 LLM usage and return alert payload when abnormal."""
    try:
        usage = get_tier3_usage_fn()
        # usage expected: {'last_min': int, 'p95_cost': float}
        if usage.get('last_min',0) > 500:  # arbitrary threshold
            msg = {'alert': 'tier3_usage_spike', 'usage': usage}
            logger.warning('Tier3 LLM usage spike: %s', usage)
            return msg
    except Exception:
        pass
    return None


def check_hopgraph_backlog(get_backlog_fn) -> Optional[dict]:
    try:
        backlog = get_backlog_fn()
        if backlog.get('inflight',0) > 1000:
            msg = {'alert': 'hopgraph_backlog', 'backlog': backlog}
            logger.warning('HopGraph backlog high: %s', backlog)
            return msg
    except Exception:
        pass
    return None
