"""Outbox stub for exactly-once-ish delivery patterns.

Provides a minimal interface; when enabled, callers should persist intent to an outbox before
attempting delivery, then mark done after success. This stub is a placeholder for integrating
with a durable store (SQLite/Postgres) and a background dispatcher.
"""
from __future__ import annotations

from typing import Any, Optional

class Outbox:
    def __init__(self) -> None:
        self._items: list[dict[str, Any]] = []

    async def put(self, item: dict[str, Any]) -> None:
        self._items.append(item)

    async def mark_done(self, item: dict[str, Any]) -> None:
        try:
            self._items.remove(item)
        except ValueError:
            pass

OUTBOX = Outbox()
