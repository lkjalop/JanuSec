from __future__ import annotations

import time
from collections import deque
from typing import Any, Deque, Dict, Optional


class TriageQueue:
    def __init__(self, domain: str):
        self.domain = domain  # email|identity|endpoint
        self.queue: Deque[Dict[str, Any]] = deque()

    def enqueue(self, event: Dict[str, Any], priority: int = 0) -> None:
        item = dict(event)
        item["triage_status"] = "queued"
        item["triage_priority"] = priority
        item["triage_timestamp"] = time.time()
        self.queue.appendleft(item) if priority > 0 else self.queue.append(item)

    def take_next(self) -> Optional[Dict[str, Any]]:
        if not self.queue:
            return None
        item = self.queue.popleft()
        item["triage_status"] = "in_progress"
        item["triage_timestamp"] = time.time()
        return item

    def mark(self, item: Dict[str, Any], verdict: str, analyst: str) -> Dict[str, Any]:
        item["triage_status"] = verdict  # confirmed|false_positive|deferred
        item["triage_verdict"] = verdict
        item["triage_analyst"] = analyst
        item["triage_timestamp"] = time.time()
        return item


__all__ = ["TriageQueue"]
