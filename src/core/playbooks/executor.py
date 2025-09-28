"""Playbook execution queue and worker.

Lightweight in-memory queue that schedules advisory actions derived from alerts.
This is a stub executor; actions are logged and stored, not actually integrated
with external systems.
"""
from __future__ import annotations
import asyncio, time, uuid, logging
from typing import List, Dict, Any, Optional, Deque, Tuple
from collections import deque
from core.playbooks.anomaly_mapping import advisory_for_alert
from repositories import playbook_executions_repo

logger = logging.getLogger(__name__)

class PlaybookTask:
    def __init__(self, alert_id: Optional[int], category: str):
        self.alert_id = alert_id
        self.category = category
        self.enqueued_at = time.time()
        self.id = str(uuid.uuid4())

class PlaybookExecutor:
    def __init__(self, max_queue: int = 1000):
        self.queue: Deque[PlaybookTask] = deque()
        self.max_queue = max_queue
        self._stop = False
        self._inflight: Dict[str, PlaybookTask] = {}
        self._executed_ids: set[str] = set()  # idempotency
        # Metrics counters (best-effort)
        try:
            from prometheus_client import Counter
            self.exec_counter = Counter('playbook_executions_total','Playbook executions',['status','category'])
        except Exception:
            self.exec_counter = None
        import os
        self.mode = os.getenv('PLAYBOOK_EXECUTION_MODE','dry-run').lower()  # 'dry-run' or 'live'

    def enqueue(self, alert_id: Optional[int], category: str) -> bool:
        if len(self.queue) >= self.max_queue:
            return False
        task = PlaybookTask(alert_id, category)
        # Idempotency: avoid duplicate category+alert combos queued rapidly
        composite = f"{alert_id}:{category}"
        if composite in self._executed_ids:
            return False
        self.queue.append(task)
        return True

    async def run(self, poll_interval: float = 1.0):
        while not self._stop:
            if not self.queue:
                await asyncio.sleep(poll_interval); continue
            task = self.queue.popleft()
            if task.id in self._executed_ids:
                continue
            self._inflight[task.id] = task
            try:
                actions = advisory_for_alert(task.category)
                # Execution behavior depends on mode
                if self.mode == 'live':
                    for act in actions:
                        logger.info(f"[playbook] LIVE action={act} category={task.category} alert_id={task.alert_id}")
                else:
                    for act in actions:
                        logger.info(f"[playbook] DRY-RUN action={act} category={task.category} alert_id={task.alert_id}")
                await playbook_executions_repo.insert_execution(task.alert_id, task.category, task.category, actions, 'success' if self.mode=='live' else 'dry-run', None)
                if self.exec_counter:
                    self.exec_counter.labels(status='success', category=task.category).inc()
            except Exception as e:
                logger.error(f"Playbook execution failed: {e}")
                try:
                    await playbook_executions_repo.insert_execution(task.alert_id, task.category, task.category, [], 'error', str(e))
                    if self.exec_counter:
                        self.exec_counter.labels(status='error', category=task.category).inc()
                except Exception:
                    pass
            finally:
                self._executed_ids.add(f"{task.alert_id}:{task.category}")
                self._inflight.pop(task.id, None)

    def stop(self):
        self._stop = True

# Singleton
_executor: PlaybookExecutor | None = None

def get_executor() -> PlaybookExecutor:
    global _executor
    if _executor is None:
        _executor = PlaybookExecutor()
    return _executor

async def start_executor_background():
    exe = get_executor()
    asyncio.create_task(exe.run())

__all__ = ['get_executor','start_executor_background','PlaybookExecutor']
