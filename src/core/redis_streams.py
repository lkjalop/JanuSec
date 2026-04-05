from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict

try:
    import aioredis as _aioredis
except Exception:  # pragma: no cover - optional dep
    try:
        # modern redis-py exposes asyncio-compatible API under redis.asyncio
        import redis.asyncio as _aioredis  # type: ignore
    except Exception:
        _aioredis = None


class RedisStreamsQueue:
    def __init__(self, redis_url: str, stream_name: str = 'ingest_stream', group_name: str = 'ingest_group', maxlen: int = 10000):
        if _aioredis is None:
            raise RuntimeError('aioredis not installed; pip install aioredis')
        self.redis_url = redis_url
        self.stream = stream_name
        self.group = group_name
        self.maxlen = maxlen
        self._client = None
        self._connected = False
        self._connect_lock = asyncio.Lock()

    async def _ensure(self):
        if self._connected and self._client:
            return
        async with self._connect_lock:
            if self._connected and self._client:
                return
            self._client = await _aioredis.from_url(self.redis_url)
            # try to create consumer group if not exists
            try:
                await self._client.xgroup_create(self.stream, self.group, id='$', mkstream=True)
            except Exception:
                # ignore if group exists
                pass
            self._connected = True

    async def enqueue(self, item: Dict[str, Any]) -> bool:
        """Append an item to the Redis Stream. Returns True on success."""
        await self._ensure()
        try:
            # use XADD with MAXLEN approx to cap stream
            payload = json.dumps(item, default=str)
            await self._client.xadd(self.stream, {'data': payload}, maxlen=self.maxlen, approximate=True)
            return True
        except Exception:
            return False

    def stats(self) -> Dict[str, int]:
        # best-effort: return length as depth
        try:
            if not self._connected or not self._client:
                # synchronous fallback: try simple sync connect
                loop = asyncio.new_event_loop()
                try:
                    client = loop.run_until_complete(_aioredis.from_url(self.redis_url))
                    length = loop.run_until_complete(client.xlen(self.stream))
                    return {'depth': int(length), 'max_size': self.maxlen}
                finally:
                    try:
                        loop.run_until_complete(client.close())
                    except Exception:
                        pass
                    loop.close()
            else:
                # if connected, use existing client but we are sync context; schedule gather
                loop = asyncio.new_event_loop()
                try:
                    length = loop.run_until_complete(self._client.xlen(self.stream))
                    return {'depth': int(length), 'max_size': self.maxlen}
                finally:
                    loop.close()
        except Exception:
            return {'depth': 0, 'max_size': self.maxlen}

    # Convenience sync wrapper for tests that don't run an event loop
    def enqueue_sync(self, item: Dict[str, Any]) -> bool:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(self.enqueue(item))
        finally:
            loop.close()


__all__ = ['RedisStreamsQueue']
