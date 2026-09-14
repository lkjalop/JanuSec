from __future__ import annotations
import os
import json
import logging
from typing import Any, Iterable, List, Optional

logger = logging.getLogger(__name__)


def get_redis_client():
    try:
        import redis as _redis  # type: ignore
    except Exception:
        return None
    red_url = os.getenv('REDIS_URL') or os.getenv('REDIS_URI')
    try:
        return _redis.from_url(red_url) if red_url else _redis.Redis()
    except Exception:
        logger.exception('Failed creating redis client')
        return None


def publish_channel(channel: str, message: Any) -> None:
    client = get_redis_client()
    if client is None:
        return
    try:
        payload = json.dumps(message, default=str)
        client.publish(channel, payload)
    except Exception:
        logger.exception('Failed publishing to channel %s', channel)


def add_parent_child(parent: str, child: str) -> None:
    client = get_redis_client()
    if client is None:
        return
    try:
        client.sadd(f'parent_children:{parent}', child)
    except Exception:
        logger.exception('Failed adding parent_child %s -> %s', parent, child)


def get_parent_children(parent: str) -> List[str]:
    client = get_redis_client()
    if client is None:
        return []
    try:
        members = client.smembers(f'parent_children:{parent}')
        result = []
        for m in members:
            try:
                if isinstance(m, bytes):
                    result.append(m.decode())
                else:
                    result.append(str(m))
            except Exception:
                continue
        return result
    except Exception:
        logger.exception('Failed fetching parent_children for %s', parent)
        return []
