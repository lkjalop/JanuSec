from __future__ import annotations

import threading
import queue
import time
from typing import Any, Dict

from .runner import PlaybookRunner, run_playbook_sync


class PlaybookQueue:
    def __init__(self, worker_count: int = 1):
        self.q: queue.Queue[Dict[str, Any]] = queue.Queue()
        self.workers: list[threading.Thread] = []
        self.worker_count = max(1, worker_count)
        self._stop = threading.Event()
        for i in range(self.worker_count):
            t = threading.Thread(target=self._worker_loop, daemon=True, name=f'pb-queue-{i}')
            t.start()
            self.workers.append(t)

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                item = self.q.get(timeout=0.5)
            except Exception:
                continue
            try:
                playbook = item.get('playbook')
                dry = bool(item.get('dry_run', True))
                # For now run synchronously inside thread (runner performs async internally)
                run_playbook_sync(playbook, dry_run=dry)
            except Exception:
                pass
            finally:
                try:
                    self.q.task_done()
                except Exception:
                    pass

    def enqueue(self, playbook: Dict[str, Any], dry_run: bool = True) -> None:
        self.q.put({'playbook': playbook, 'dry_run': dry_run})

    def stop(self) -> None:
        self._stop.set()
        # drain queue
        try:
            while not self.q.empty():
                self.q.get_nowait()
                self.q.task_done()
        except Exception:
            pass


_GLOBAL_QUEUE: PlaybookQueue | None = None


def get_global_queue() -> PlaybookQueue:
    global _GLOBAL_QUEUE
    if _GLOBAL_QUEUE is None:
        _GLOBAL_QUEUE = PlaybookQueue(worker_count=int(__import__('os').getenv('PLAYBOOK_QUEUE_WORKERS','1')))
    return _GLOBAL_QUEUE


def shutdown_global_queue() -> None:
    global _GLOBAL_QUEUE
    if _GLOBAL_QUEUE is not None:
        _GLOBAL_QUEUE.stop()
        _GLOBAL_QUEUE = None


__all__ = ['get_global_queue', 'shutdown_global_queue']
