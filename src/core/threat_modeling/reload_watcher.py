"""Hot-reload watcher for scenarios (Phase 1 implementation).

This lightweight implementation polls a directory for *.py or *.yaml changes.
Future iterations can add YAML parsing & validation; for now we only support
Python-based scenario definitions (pasta_scenarios.py).
"""
from __future__ import annotations

import importlib
import logging
import os
import threading
import time
import traceback
from typing import Optional

from . import pasta_scenarios
from .scenario_engine import ENGINE

logger = logging.getLogger(__name__)

class ScenarioReloader:
    def __init__(self, path: str, interval: float = 10.0) -> None:
        self.path = path
        self.interval = interval
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._last_mtime = 0.0
        self.reload_count = 0
        self.failure_count = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name='scenario-reloader', daemon=True)
        self._thread.start()
        logger.info("ScenarioReloader started path=%s interval=%s", self.path, self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                logger.warning("ScenarioReloader tick failed:\n%s", traceback.format_exc())
            self._stop.wait(self.interval)

    def _tick(self):
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return
        if mtime <= self._last_mtime:
            return
        self._last_mtime = mtime
        self._do_reload()

    def _do_reload(self):
        try:
            importlib.reload(pasta_scenarios)
            # Replace engine scenarios atomically
            ENGINE.scenarios = list(pasta_scenarios.SCENARIOS)
            self.reload_count += 1
            logger.info("Scenarios hot-reloaded (%d total)", self.reload_count)
        except Exception:
            self.failure_count += 1
            logger.error("Scenario reload failed:\n%s", traceback.format_exc())

# Singleton watcher (opt-in)
WATCHER: ScenarioReloader | None = None

def ensure_watcher():
    global WATCHER
    if WATCHER is not None:
        return WATCHER
    path = os.getenv('SCENARIO_FILE_PATH') or os.path.join(os.path.dirname(__file__), 'pasta_scenarios.py')
    interval = float(os.getenv('SCENARIO_RELOAD_INTERVAL','15') or 15)
    enabled = os.getenv('SCENARIO_HOT_RELOAD','0').lower() in {'1','true','yes'}
    if not enabled:
        return None
    WATCHER = ScenarioReloader(path, interval=interval)
    WATCHER.start()
    return WATCHER

__all__ = ['ensure_watcher','ScenarioReloader']
