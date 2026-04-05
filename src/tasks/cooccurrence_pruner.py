"""Background maintenance task for co-occurrence store.

Provides a simple pruning loop and exposes a one-shot prune function suitable
for integration into existing scheduler or as a startup background task.
"""
from __future__ import annotations

import time
import threading
from typing import Optional
from src.graph.cooccurrence import prune_older, stats  # type: ignore
from src.api.metrics_init import ensure_metrics, cooccurrence_unique_pairs  # type: ignore

_stop = threading.Event()

def prune_once(threshold_seconds: int = 60*60*24*7) -> int:
    removed = prune_older(threshold_seconds)
    # update metrics if available
    try:
        ensure_metrics()
        up = stats().get('unique_pairs')
        cooccurrence_unique_pairs.set(up or 0)
    except Exception:
        pass
    return removed

def run_loop(interval_seconds: int = 60*60, threshold_seconds: int = 60*60*24*7):
    """Run pruning loop until stopped. Blocks current thread.

    Typically run in a background thread or supervisor.
    """
    while not _stop.is_set():
        try:
            prune_once(threshold_seconds)
        except Exception:
            pass
        _stop.wait(interval_seconds)

def start_background(interval_seconds: int = 60*60, threshold_seconds: int = 60*60*24*7) -> threading.Thread:
    t = threading.Thread(target=run_loop, args=(interval_seconds, threshold_seconds), daemon=True)
    t.start()
    return t

def stop_background() -> None:
    _stop.set()
