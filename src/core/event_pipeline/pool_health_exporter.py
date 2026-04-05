import asyncio
import time
from typing import Optional

from src.core.event_pipeline.process_workers import pool_health
from src.core.event_pipeline.metrics import PipelineMetrics


async def pool_health_loop(interval_seconds: int = 10):
    while True:
        try:
            h = pool_health()
            restarts = int(h.get('restarts') or 0)
            last_err = bool(h.get('last_error'))
            healthy = bool(h.get('healthy'))
            try:
                PipelineMetrics().set_pool_health(restarts, last_err, healthy)
            except Exception:
                pass
        except Exception:
            pass
        await asyncio.sleep(max(1, int(interval_seconds)))
