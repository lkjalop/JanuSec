from __future__ import annotations
import json
import logging
import asyncio
from typing import Any, Mapping
import redis.asyncio as aioredis

LOGGER = logging.getLogger(__name__)


class RedisStreamProducer:
    def __init__(self, url: str = 'redis://localhost:6379/0', *, stream_prefix: str = 'collectors') -> None:
        self._url = url
        self._stream_prefix = stream_prefix
        self._client: aioredis.Redis | None = None

    async def connect(self):
        if self._client is None:
            self._client = aioredis.from_url(self._url, encoding='utf-8', decode_responses=True)
            try:
                await self._client.ping()
            except Exception as exc:
                LOGGER.exception('Redis ping failed: %s', exc)

    async def push(self, stream_name: str, payload: Mapping[str, Any]) -> str:
        """Push JSON-serializable payload to Redis Stream and return message id."""
        if self._client is None:
            await self.connect()
        key = f"{self._stream_prefix}:{stream_name}"
        try:
            # ensure payload values are strings
            body = {k: json.dumps(v, default=str) for k, v in payload.items()}
            msgid = await self._client.xadd(key, body, maxlen=None)
            return msgid
        except Exception:
            LOGGER.exception('Failed to push to redis stream %s', key)
            raise

    async def backlog_len(self, stream_name: str) -> int:
        if self._client is None:
            await self.connect()
        return await self._client.xlen(f"{self._stream_prefix}:{stream_name}")

    async def close(self):
        try:
            if self._client:
                await self._client.close()
        except Exception:
            pass

    async def try_acquire_token(self, key: str, capacity: int, refill_per_sec: float, cost: float = 1.0) -> bool:
        """
        Try to acquire a token for `key` using a Redis-based token bucket.
        Returns True if token acquired, False otherwise.
        """
        if self._client is None:
            await self.connect()

        # Lua script performs atomic token bucket update
        script = r"""
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local capacity = tonumber(ARGV[2])
        local refill = tonumber(ARGV[3])
        local cost = tonumber(ARGV[4])
        local data = redis.call('HMGET', key, 'tokens', 'last')
        local tokens = tonumber(data[1]) or capacity
        local last = tonumber(data[2]) or now
        local elapsed = math.max(0, now - last)
        tokens = math.min(capacity, tokens + elapsed * refill)
        if tokens < cost then
            -- update last and tokens
            redis.call('HMSET', key, 'tokens', tokens, 'last', now)
            redis.call('EXPIRE', key, 3600)
            return 0
        else
            tokens = tokens - cost
            redis.call('HMSET', key, 'tokens', tokens, 'last', now)
            redis.call('EXPIRE', key, 3600)
            return 1
        end
        """
        try:
            now = int((await self._client.time())[0])
            res = await self._client.eval(script, 1, key, now, capacity, refill_per_sec, cost)
            return bool(res)
        except Exception:
            # On Redis error, fall back to allow (so ingestion isn't blocked entirely)
            return True

    async def get_token_bucket(self, key: str):
        """Return token bucket state for key or None."""
        if self._client is None:
            await self.connect()
        try:
            data = await self._client.hgetall(key)
            if not data:
                return None
            return {k: float(v) for k, v in data.items()}
        except Exception:
            return None
