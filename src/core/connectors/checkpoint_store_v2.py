import json
import os
import tempfile
import time
from typing import Optional, Dict, Any

SCHEMA_VERSION = 2

class CheckpointStoreV2:
    """
    Unified checkpoint store with atomic writes and simple corruption recovery.
    Schema: {source, stream_id, cursor, timestamp, watermark, version}
    """

    def __init__(self, base_path: Optional[str] = None):
        # In test mode prefer an ephemeral per-process directory to avoid
        # clobbering checkpoints between test runs. Honor explicit base_path
        # or CONNECTOR_CHECKPOINTS_PATH when provided.
        env_path = os.getenv("CONNECTOR_CHECKPOINTS_PATH")
        fast_test = os.getenv('FAST_TEST_MODE', '0').lower() in {'1', 'true', 'yes'} or 'PYTEST_CURRENT_TEST' in os.environ
        if base_path:
            self.base_path = base_path
        elif env_path:
            self.base_path = env_path
        elif fast_test:
            unique = f"cp_test_{os.getpid()}_{int(time.time()*1000)}"
            self.base_path = os.path.join(tempfile.gettempdir(), unique)
        else:
            self.base_path = tempfile.gettempdir()
        os.makedirs(self.base_path, exist_ok=True)

    def _path(self, source: str, stream_id: str) -> str:
        # sanitize filename to avoid invalid characters on Windows (e.g. ':')
        raw = f"cp_{source}_{stream_id}"
        safe = []
        for ch in raw:
            if ch.isalnum() or ch in ('-', '_'):
                safe.append(ch)
            else:
                safe.append('_')
        fname = ''.join(safe) + '.json'
        return os.path.join(self.base_path, fname)

    def load(self, source: str, stream_id: str) -> Optional[Dict[str, Any]]:
        path = self._path(source, stream_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # basic schema guard
            if isinstance(data, dict) and data.get("version") == SCHEMA_VERSION:
                return data
        except Exception:
            return None
        return None

    def save(self, source: str, stream_id: str, payload: Dict[str, Any]) -> None:
        path = self._path(source, stream_id)
        payload = dict(payload)
        payload.setdefault("version", SCHEMA_VERSION)
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
