"""Logging utilities: backoff / frequency-suppressed emission.

Provides log_backoff(logger, key, level, message, first_n=1, ratio=10)
that emits the first `first_n` occurrences of a keyed message immediately,
then every Nth occurrence growing by `ratio` (geometric style):

Example emission schedule with first_n=1, ratio=10:
  1 (immediate), 10, 20, 30, 40, 50, ... (every +10)  -- simple linear after first
If ratio > 1 and first_n > 1 we can adapt to geometric growth; we keep it
linear for operator predictability (emit every `ratio` occurrences after the
initial burst). This keeps implementation simple and deterministic.

Thread-safe via internal lock; lightweight dictionary of counters.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable, Dict

_lock = threading.Lock()
_counters: Dict[str, int] = {}

def log_backoff(
    logger: logging.Logger,
    key: str,
    level: int,
    message: str,
    *,
    first_n: int = 1,
    ratio: int = 10,
    emit: Callable[[int,str], None] | None = None,
) -> None:
    """Emit a log line with frequency suppression.

    Parameters:
        logger: target logger
        key: semantic key grouping repeated messages (stable hash / pattern id)
        level: logging level (e.g. logging.WARNING)
        message: message text (already formatted)
        first_n: emit unconditionally for the first N occurrences
        ratio: after first_n, emit every `ratio`th occurrence
        emit: optional hook called with (count, message) when emitting (testing)
    """
    if ratio <= 0:
        ratio = 10
    if first_n < 0:
        first_n = 0
    with _lock:
        count = _counters.get(key, 0) + 1
        _counters[key] = count
        should_emit = count <= first_n or (count - first_n) % ratio == 0
    if not should_emit:
        return
    try:
        logger.log(level, "%s (occurrence=%d)%s", message, count,
                   "" if count <= first_n else " [suppressed backoff]")
    except Exception:
        # Fallback in catastrophic logger failure
        if emit:
            emit(count, message)
        return
    if emit:
        try:
            emit(count, message)
        except Exception:
            pass

__all__ = ["log_backoff"]
