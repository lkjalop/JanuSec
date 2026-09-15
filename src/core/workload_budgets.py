"""Independent concurrency budgets for generation and embedding workloads."""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from typing import Iterator


EMBEDDING_CONCURRENCY = max(1, int(os.getenv("MODEL_EMBEDDING_CONCURRENCY", "1") or 1))
_EMBEDDING_SEMAPHORE = threading.BoundedSemaphore(EMBEDDING_CONCURRENCY)


@contextmanager
def embedding_slot(timeout_seconds: float | None = None) -> Iterator[None]:
    timeout = timeout_seconds
    if timeout is None:
        timeout = float(os.getenv("MODEL_EMBEDDING_QUEUE_TIMEOUT_SECONDS", "30") or 30)
    acquired = _EMBEDDING_SEMAPHORE.acquire(timeout=max(0.0, timeout))
    if not acquired:
        raise TimeoutError("embedding_concurrency_budget_exhausted")
    try:
        yield
    finally:
        _EMBEDDING_SEMAPHORE.release()


__all__ = ["EMBEDDING_CONCURRENCY", "embedding_slot"]
