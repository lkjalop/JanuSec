from __future__ import annotations
import asyncio
from typing import List, Dict, Any
from datetime import datetime

from src.schemas.email import NormalizedEmailEvent


class CofenseConfig:
    def __init__(self, api_token: str, base_url: str = "https://vision.cofense.com/api/v2", poll_interval_seconds: int = 60):
        self.api_token = api_token
        self.base_url = base_url
        self.poll_interval_seconds = poll_interval_seconds


class CofenseConnector:
    """Lightweight Cofense Vision connector scaffold.

    This module is intentionally minimal and import-safe for tests. It
    provides the contract expected by the MD and by later integration.
    """

    def __init__(self, cfg: CofenseConfig):
        self.cfg = cfg
        self._last_poll = datetime.utcnow()

    async def fetch_reported_threats(self) -> List[NormalizedEmailEvent]:
        """Fetch user-reported threats from Cofense.

        NOTE: This is a scaffold. Implement actual HTTP calls and rate
        limiting in production.
        """
        await asyncio.sleep(0)
        # Return empty list as safe default
        return []

    async def search_similar_messages(self, iocs: Dict[str, List[str]], tenant_id: str) -> List[Dict[str, Any]]:
        await asyncio.sleep(0)
        return []

    async def quarantine_similar_messages(self, message_ids: List[str], reason: str) -> Dict[str, Any]:
        await asyncio.sleep(0)
        return {"quarantined": [], "requested": len(message_ids)}
