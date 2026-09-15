import os
import json
import time
import threading
from typing import Optional

from ..repositories import incidents_repo

OUTBOX_PATH = os.environ.get("INCIDENT_AUTOGEN_OUTBOX")
POLL_INTERVAL = float(os.environ.get("INCIDENT_AUTOGEN_OUTBOX_POLL_SECONDS", "2.0"))


class OutboxConsumer:
    def __init__(self, outbox_path: Optional[str] = None, poll_interval: float = POLL_INTERVAL):
        self.outbox_path = outbox_path or OUTBOX_PATH
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if not self.outbox_path:
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0):
        if not self._thread:
            return
        self._stop_event.set()
        self._thread.join(timeout=timeout)

    def _run(self):
        # Read appended JSONL from outbox file; on success, persist and truncate processed lines
        while not self._stop_event.is_set():
            try:
                if not os.path.exists(self.outbox_path):
                    time.sleep(self.poll_interval)
                    continue

                # Read all lines, attempt to persist them in order
                with open(self.outbox_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()

                if not lines:
                    time.sleep(self.poll_interval)
                    continue

                remaining = []
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        incident = json.loads(line)
                    except Exception:
                        # corrupt line: keep in outbox (move to remaining)
                        remaining.append(line)
                        continue

                    try:
                        # call repository upsert (async function may exist; handle sync)
                        coro = incidents_repo.upsert_incident(incident)
                        # If upsert_incident is asynchronous, run it synchronously using asyncio
                        import asyncio

                        if asyncio.iscoroutine(coro):
                            asyncio.run(coro)
                    except Exception:
                        # persistence failed: keep this line and stop processing further to preserve ordering
                        remaining.append(line)
                        break

                # Write back remaining lines atomically
                tmp_path = self.outbox_path + ".tmp"
                with open(tmp_path, "w", encoding="utf-8") as f:
                    for r in remaining:
                        f.write(r + "\n")
                os.replace(tmp_path, self.outbox_path)

            except Exception:
                # Global error — sleep and retry
                time.sleep(self.poll_interval)
                continue

            time.sleep(self.poll_interval)


consumer = OutboxConsumer()
