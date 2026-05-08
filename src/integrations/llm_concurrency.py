"""Shared concurrency limiter for outbound LLM calls."""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from typing import Iterator


class LLMConcurrencyLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._semaphore: threading.BoundedSemaphore | None = None
        self._limit = 0
        self.active = 0
        self.queue_depth = 0    # currently waiting (live counter)
        self.wait_count = 0     # cumulative total waits since start
        self.timeout_count = 0  # cumulative total timeouts since start

    def _configured_limit(self) -> int:
        raw = os.getenv("LLM_MAX_CONCURRENT") or os.getenv("OLLAMA_MAX_CONCURRENT") or "4"
        try:
            return max(1, int(raw))
        except Exception:
            return 4

    def _queue_timeout(self) -> float:
        raw = os.getenv("LLM_QUEUE_TIMEOUT_SECONDS") or "120"
        try:
            return max(0.0, float(raw))
        except Exception:
            return 120.0

    def _ensure(self) -> threading.BoundedSemaphore:
        limit = self._configured_limit()
        with self._lock:
            if self._semaphore is None or self._limit != limit:
                self._semaphore = threading.BoundedSemaphore(limit)
                self._limit = limit
                self.active = 0
        return self._semaphore

    @contextmanager
    def acquire(self, *, label: str = "llm") -> Iterator[dict[str, float | int | str]]:
        semaphore = self._ensure()
        timeout = self._queue_timeout()
        start = time.time()
        with self._lock:
            self.wait_count += 1
            self.queue_depth += 1
        acquired = semaphore.acquire(timeout=timeout)
        wait_s = time.time() - start
        with self._lock:
            self.queue_depth = max(0, self.queue_depth - 1)
        if not acquired:
            with self._lock:
                self.timeout_count += 1
            raise TimeoutError(f"{label} concurrency queue exceeded {timeout:.1f}s")
        with self._lock:
            self.active += 1
            active = self.active
            limit = self._limit
        try:
            yield {"wait_s": wait_s, "active": active, "limit": limit, "label": label}
        finally:
            with self._lock:
                self.active = max(0, self.active - 1)
            semaphore.release()

    def snapshot(self) -> dict[str, int]:
        self._ensure()
        with self._lock:
            return {
                "limit": self._limit,
                "active": self.active,
                "queue_depth": self.queue_depth,
                "wait_count": self.wait_count,
                "timeout_count": self.timeout_count,
            }


GLOBAL_LLM_LIMITER = LLMConcurrencyLimiter()


def llm_concurrency_status() -> dict[str, int]:
    return GLOBAL_LLM_LIMITER.snapshot()
