from __future__ import annotations
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
import threading
import os
import logging

logger = logging.getLogger(__name__)


class CRQPersistence:
    def persist(self, obs: Dict[str, Any]) -> None:
        raise NotImplementedError()

    def read_all(self) -> List[Dict[str, Any]]:
        raise NotImplementedError()


class FileCRQPersistence(CRQPersistence):
    def __init__(self, path: Optional[str] = None):
        p = path or os.environ.get('CRQ_PERSIST_PATH') or 'data/crq_shadow.json'
        self.path = Path(p)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def persist(self, obs: Dict[str, Any]) -> None:
        # atomic append via read-modify-write to temp file
        with self._lock:
            arr = []
            try:
                if self.path.exists():
                    arr = json.loads(self.path.read_text(encoding='utf-8') or '[]')
            except Exception:
                arr = []
            arr.append(obs)
            tmp = self.path.with_suffix('.tmp')
            try:
                tmp.write_text(json.dumps(arr), encoding='utf-8')
                # fsync not available via Pathlib; best-effort
                tmp.replace(self.path)
                # Instrumentation: log absolute path and timestamp when writing
                try:
                    logger.debug("CRQ_PERSIST: wrote %d items to %s at %s", len(arr), str(self.path.resolve()), time.time())
                except Exception:
                    pass
            except Exception:
                # swallow to remain best-effort
                pass

    def read_all(self) -> List[Dict[str, Any]]:
        try:
            if self.path.exists():
                return json.loads(self.path.read_text(encoding='utf-8') or '[]')
        except Exception:
            return []
        return []


class InMemoryCRQPersistence(CRQPersistence):
    def __init__(self):
        self._arr: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def persist(self, obs: Dict[str, Any]) -> None:
        with self._lock:
            self._arr.append(obs)
            try:
                logger.debug("CRQ_PERSIST: in-memory persist %d items at %s", len(self._arr), time.time())
            except Exception:
                pass

    def read_all(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._arr)
