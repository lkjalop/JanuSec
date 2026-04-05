from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, Optional

from .runner import PlaybookRunner


class PlaybookAsyncQueue:
    def __init__(self, worker_count: int = 1) -> None:
        self.q: asyncio.Queue = asyncio.Queue()
        self.worker_count = max(1, worker_count)
        self.tasks: list[asyncio.Task] = []
        self.processed_count = 0
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        loop = asyncio.get_running_loop()
        for _ in range(self.worker_count):
            t = loop.create_task(self._worker_loop())
            self.tasks.append(t)
        self._started = True

    async def _worker_loop(self) -> None:
        try:
            while True:
                try:
                    item = await self.q.get()
                except RuntimeError:
                    # Event loop closed; exit worker cleanly
                    return
                try:
                    playbook = item.get('playbook')
                    dry = bool(item.get('dry_run', True))
                    runner = PlaybookRunner(dry_run=dry)
                    # runner.run is async
                    await runner.run(playbook)
                    self.processed_count += 1
                except asyncio.CancelledError:
                    # Propagate cancellation to allow clean exit
                    raise
                except Exception:
                    pass
                finally:
                    try:
                        self.q.task_done()
                    except Exception:
                        pass
        except asyncio.CancelledError:
            # worker was cancelled, exit cleanly
            return

    async def enqueue(self, playbook: Dict[str, Any], dry_run: bool = True) -> None:
        await self.start()
        await self.q.put({'playbook': playbook, 'dry_run': dry_run})

    def qsize(self) -> int:
        return self.q.qsize()

    async def shutdown(self) -> None:
        # Cancel and await worker tasks
        for t in list(self.tasks):
            try:
                t.cancel()
            except Exception:
                pass
        if self.tasks:
            try:
                await asyncio.gather(*self.tasks, return_exceptions=True)
            except Exception:
                pass
        self.tasks.clear()
        self._started = False


_GLOBAL_ASYNC_Q: Optional[PlaybookAsyncQueue] = None


async def get_global_queue_async() -> PlaybookAsyncQueue:
    global _GLOBAL_ASYNC_Q
    if _GLOBAL_ASYNC_Q is None:
        workers = int(__import__('os').getenv('PLAYBOOK_QUEUE_WORKERS', '1'))
        _GLOBAL_ASYNC_Q = PlaybookAsyncQueue(worker_count=workers)
        await _GLOBAL_ASYNC_Q.start()
    return _GLOBAL_ASYNC_Q


async def shutdown_global_queue_async() -> None:
    global _GLOBAL_ASYNC_Q
    if _GLOBAL_ASYNC_Q is not None:
        await _GLOBAL_ASYNC_Q.shutdown()
        _GLOBAL_ASYNC_Q = None


__all__ = ['get_global_queue_async', 'shutdown_global_queue_async']
