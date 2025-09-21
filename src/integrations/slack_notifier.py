"""Async Slack Notifier with basic rate limiting"""
from __future__ import annotations
import asyncio
import time
import json
import logging
from typing import Optional

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

logger = logging.getLogger(__name__)

class SlackNotifier:
    def __init__(self, webhook_url: Optional[str], default_channel: Optional[str], channel_map: dict[str, str] | None, rate_limit_per_minute: int = 30):
        self.webhook_url = webhook_url
        self.default_channel = default_channel
        self.channel_map = channel_map or {}
        self.rate_limit_per_minute = rate_limit_per_minute
        self._tokens = rate_limit_per_minute
        self._last_refill = time.time()
        self._lock = asyncio.Lock()

    async def _refill(self):
        now = time.time()
        elapsed = now - self._last_refill
        if elapsed >= 60:
            self._tokens = self.rate_limit_per_minute
            self._last_refill = now

    async def send_alert(self, severity: str, text: str, blocks: list | None = None) -> bool:
        if not self.webhook_url or httpx is None:
            return False
        async with self._lock:
            await self._refill()
            if self._tokens <= 0:
                logger.warning("Slack rate limit hit; dropping message")
                return False
            self._tokens -= 1
        channel = self.channel_map.get(severity.lower()) or self.default_channel
        payload = {"text": text}
        if channel:
            payload["channel"] = channel
        if blocks:
            payload["blocks"] = blocks
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(self.webhook_url, json=payload)
                if resp.status_code >= 300:
                    logger.warning(f"Slack post failed: {resp.status_code} {resp.text}")
                    return False
                return True
        except Exception as e:  # pragma: no cover
            logger.debug(f"Slack send exception: {e}")
            return False
