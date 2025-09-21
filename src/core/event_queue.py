"""Event Queue & Backpressure Handling

Provides bounded asyncio Queue, overflow handling, metrics hooks.
"""
import asyncio
import time
from typing import Any, Dict, Optional, Callable
import logging

try:
    from prometheus_client import Gauge, Counter
except Exception:  # graceful if not installed
    Gauge = lambda *a, **k: None  # type: ignore
    Counter = lambda *a, **k: None  # type: ignore

logger = logging.getLogger(__name__)

class EventQueue:
    def __init__(self, max_size: int = 1000, overflow_policy: str = "drop_oldest"):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=max_size)
        self.overflow_policy = overflow_policy  # drop_oldest | drop_new | block
        self.dropped_events = 0
        self.accepted_events = 0
        self.last_enqueue_ts = 0.0
        self.last_dequeue_ts = 0.0
        self._init_metrics()

    def _init_metrics(self):
        if getattr(self.__class__, '_metrics_initialized', False):
            return
        try:
            self.__class__.queue_depth = Gauge('event_queue_depth', 'Current depth of event queue')
            self.__class__.queue_dropped = Counter('event_queue_dropped_total', 'Total dropped events')
            self.__class__.queue_enqueued = Counter('event_queue_enqueued_total', 'Total accepted events')
            self.__class__._metrics_initialized = True
        except Exception:
            pass

    async def enqueue(self, event: Dict[str, Any]) -> bool:
        if self.queue.full():
            if self.overflow_policy == 'drop_new':
                self.dropped_events += 1
                self._observe(drop=True)
                return False
            elif self.overflow_policy == 'drop_oldest':
                try:
                    _ = self.queue.get_nowait()  # discard oldest
                    self.queue.task_done()
                except Exception:
                    pass
            elif self.overflow_policy == 'block':
                # Just fall through to put() which will block
                pass
        await self.queue.put(event)
        self.accepted_events += 1
        self.last_enqueue_ts = time.time()
        self._observe()
        return True

    async def dequeue(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        try:
            if timeout:
                event = await asyncio.wait_for(self.queue.get(), timeout=timeout)
            else:
                event = await self.queue.get()
            self.last_dequeue_ts = time.time()
            self._observe()
            return event
        except asyncio.TimeoutError:
            return None

    def _observe(self, drop: bool = False):
        try:
            if hasattr(self.__class__, 'queue_depth') and self.__class__.queue_depth:
                self.__class__.queue_depth.set(self.queue.qsize())
            if drop and hasattr(self.__class__, 'queue_dropped') and self.__class__.queue_dropped:
                self.__class__.queue_dropped.inc()
            elif not drop and hasattr(self.__class__, 'queue_enqueued') and self.__class__.queue_enqueued:
                self.__class__.queue_enqueued.inc()
        except Exception:
            pass

    def stats(self) -> Dict[str, Any]:
        return {
            'depth': self.queue.qsize(),
            'accepted_events': self.accepted_events,
            'dropped_events': self.dropped_events,
            'overflow_policy': self.overflow_policy,
            'last_enqueue_ts': self.last_enqueue_ts,
            'last_dequeue_ts': self.last_dequeue_ts
        }
