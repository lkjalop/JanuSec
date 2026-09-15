from __future__ import annotations
import asyncio
import json
import logging
import os
from typing import Any

from .redis_helpers import get_redis_client

logger = logging.getLogger(__name__)


async def _run_subscriber(app) -> None:
    """Background task that subscribes to assessment event channels and forwards
    messages to in-process SSE broadcasters (if present) so other processes
    can receive published events via Redis.

    This is best-effort: if Redis isn't configured or errors occur, the task
    logs and exits silently.
    """
    client = get_redis_client()
    if client is None:
        logger.info('Redis pubsub disabled (no client)')
        return
    try:
        pubsub = client.pubsub(ignore_subscribe_messages=True)
        # subscribe to assessment events pattern
        pattern = os.getenv('REDIS_ASSESSMENT_EVENTS_PATTERN', 'assessment:events:*')
        await asyncio.get_event_loop().run_in_executor(None, pubsub.psubscribe, pattern)
    except Exception:
        logger.exception('Failed to initialize Redis pubsub subscriber')
        return

    logger.info('Redis pubsub subscriber started, pattern=%s', pattern)

    try:
        # Blocking loop listening for messages
        while True:
            try:
                msg = await asyncio.get_event_loop().run_in_executor(None, pubsub.get_message, True, 1)
                if not msg:
                    await asyncio.sleep(0.1)
                    continue
                # msg is dict with data/raw type
                try:
                    data = msg.get('data')
                    if isinstance(data, (bytes, bytearray)):
                        payload = json.loads(data.decode())
                    elif isinstance(data, str):
                        payload = json.loads(data)
                    else:
                        payload = data
                except Exception:
                    payload = msg.get('data')
                channel = msg.get('channel') or msg.get('pattern')
                try:
                    # forward to in-process broadcasters if exposed on app.state
                    broadcasters = getattr(app.state, '_sse_broadcasters', None) or getattr(app.state, '_SSE_BROADCASTERS', None)
                    if broadcasters:
                        # broadcasters expected to be dict[channel] -> list[callables]
                        try:
                            listeners = broadcasters.get(channel) if isinstance(broadcasters, dict) else None
                            if listeners:
                                for cb in list(listeners):
                                    try:
                                        cb(payload)
                                    except Exception:
                                        logger.exception('SSE broadcaster callback failed')
                        except Exception:
                            logger.exception('Forward to broadcasters failed')
                except Exception:
                    logger.exception('Forwarding pubsub message failed')
            except Exception:
                # make loop resilient to transient Redis errors
                logger.exception('Redis pubsub loop error, sleeping briefly')
                await asyncio.sleep(1)
    finally:
        try:
            await asyncio.get_event_loop().run_in_executor(None, pubsub.close)
        except Exception:
            pass


def start_redis_subscriber(app) -> None:
    """Start the Redis subscriber as an asyncio background task on the given FastAPI app."""
    try:
        # avoid starting in test/lite modes
        if os.getenv('FAST_TEST_MODE','').lower() in {'1','true','yes'} or os.getenv('PLATFORM_LITE_INIT','').lower() in {'1','true','yes'}:
            logger.info('Skipping Redis subscriber in test/lite mode')
            return
        loop = asyncio.get_event_loop()
        task = loop.create_task(_run_subscriber(app))
        # attach for shutdown management
        try:
            app.state._redis_pubsub_task = task
        except Exception:
            pass
    except Exception:
        logger.exception('Failed to start redis subscriber')
