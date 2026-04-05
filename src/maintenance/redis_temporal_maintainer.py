"""Periodic maintenance for RedisTemporalCache.

Calls cleanup_hosts() periodically to remove stale hosts from the host set.
Enabled by env var REDIS_TEMPORAL_MAINTENANCE_ENABLED (defaults to false).
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


async def maintenance_loop(stop_event: asyncio.Event, cache_factory, interval_seconds: int | None = None):
    """cache_factory: callable that returns a cache instance (may be build_cache)
    stop_event: asyncio.Event to cancel the loop
    """
    enabled = os.getenv('REDIS_TEMPORAL_MAINTENANCE_ENABLED', '0').lower() in {'1', 'true', 'yes'}
    if not enabled:
        logger.debug('Redis temporal maintenance disabled via env')
        return

    if interval_seconds is None:
        interval_seconds = int(os.getenv('REDIS_TEMPORAL_MAINTENANCE_INTERVAL', '300'))

    # attempt to construct the cache; if it fails, exit quietly
    try:
        redis_url = os.getenv('REDIS_URL')
        cache = cache_factory(redis_url)
    except Exception as exc:
        logger.debug('Redis temporal cache factory failed: %s', exc)
        return

    logger.info('Starting Redis temporal cache maintenance loop (interval=%ds)', interval_seconds)
    while not stop_event.is_set():
        try:
            removed = cache.cleanup_hosts()
            if removed:
                logger.info('Redis temporal maintenance removed %d stale hosts', removed)
        except Exception as exc:
            logger.debug('Redis temporal maintenance error: %s', exc)
        await asyncio.sleep(interval_seconds)
