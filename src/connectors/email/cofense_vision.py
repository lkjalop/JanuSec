"""Minimal Cofense Vision connector scaffold (P0 human-signal).

This module provides a lightweight, import-safe connector that can be
expanded to implement full polling, webhook or push integration with Cofense.
It returns `NormalizedEmailEvent` objects for downstream processing.
"""
from __future__ import annotations
from typing import List
from datetime import datetime
import asyncio
import logging

from src.schemas.email import NormalizedEmailEvent

LOGGER = logging.getLogger(__name__)


class CofenseConfig:
    def __init__(self, api_token: str, base_url: str = "https://vision.cofense.com/api/v2", poll_interval_seconds: int = 60):
        self.api_token = api_token
        self.base_url = base_url
        self.poll_interval_seconds = poll_interval_seconds


class CofenseVisionConnector:
    def __init__(self, config: CofenseConfig):
        self.config = config
        self._last_poll = datetime.utcnow()

    async def fetch_reported_threats(self) -> List[NormalizedEmailEvent]:
        """Stub: fetch recent user-reported phishing events and normalize them.

        In production implement API calls with aiohttp, pagination, error handling.
        """
        # Minimal stub: return empty list to keep import/test safe
        await asyncio.sleep(0)
        LOGGER.debug("CofenseVisionConnector.fetch_reported_threats: stub called")
        return []


__all__ = ["CofenseConfig", "CofenseVisionConnector"]
