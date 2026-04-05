"""Simple async circuit breaker for external feed calls.

Usage:
    breaker = CircuitBreaker('opencti')
    async with breaker.guard():
        await call()

Env vars:
  CB_FAILURE_THRESHOLD (default 5)
  CB_RESET_SECONDS (default 60)
"""
from __future__ import annotations
import time, asyncio, os, logging
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

class CircuitBreaker:
    def __init__(self, name: str):
        self.name = name
        self.failure_threshold = int(os.getenv('CB_FAILURE_THRESHOLD','5') or 5)
        self.reset_seconds = float(os.getenv('CB_RESET_SECONDS','60') or 60)
        self.failures = 0
        self.opened_at: float | None = None
        self.lock = asyncio.Lock()

    def is_open(self) -> bool:
        if self.opened_at is None:
            return False
        if (time.time() - self.opened_at) >= self.reset_seconds:
            # half-open trial
            return False
        return True

    async def record_success(self):
        async with self.lock:
            self.failures = 0
            self.opened_at = None

    async def record_failure(self):
        async with self.lock:
            self.failures += 1
            if self.failures >= self.failure_threshold:
                if self.opened_at is None:
                    self.opened_at = time.time()
                    logger.warning("Circuit opened for %s", self.name)

    @asynccontextmanager
    async def guard(self):
        if self.is_open():
            raise RuntimeError(f'circuit_open:{self.name}')
        try:
            yield
        except Exception:
            await self.record_failure()
            raise
        else:
            await self.record_success()

_CIRCUITS: dict[str,CircuitBreaker] = {}

def get_circuit(name: str) -> CircuitBreaker:
    cb = _CIRCUITS.get(name)
    if not cb:
        cb = CircuitBreaker(name); _CIRCUITS[name] = cb
    return cb

__all__ = ['get_circuit','CircuitBreaker']