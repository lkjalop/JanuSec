"""Simple persistence for per-tenant polling metadata (delta links, history IDs)."""
from __future__ import annotations

import json
import os
import threading
from typing import Dict, Optional


class PollingStateStore:
    def __init__(self, root_dir: Optional[str] = None):
        default_dir = os.path.join(os.path.dirname(__file__), "..", "data", "polling_state")
        self.root = root_dir or os.environ.get("POLLING_STATE_DIR") or default_dir
        os.makedirs(self.root, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, tenant_id: str, provider: str) -> str:
        safe_tenant = tenant_id.replace("/", "_")
        safe_provider = provider.replace("/", "_")
        return os.path.join(self.root, f"{safe_tenant}_{safe_provider}.json")

    def load_state(self, tenant_id: str, provider: str) -> Dict:
        path = self._path(tenant_id, provider)
        if not os.path.exists(path):
            return {}
        with self._lock:
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except Exception:
                # Corrupt or transient read issue: return empty state so polling can recover
                try:
                    # best-effort cleanup of corrupted file to avoid repeated failures
                    os.remove(path)
                except Exception:
                    pass
                return {}

    def save_state(self, tenant_id: str, provider: str, state: Dict) -> None:
        path = self._path(tenant_id, provider)
        # Atomic write using temp file + replace while holding lock
        tmp = f"{path}.tmp"
        with self._lock:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(state, fh, indent=2)
            try:
                os.replace(tmp, path)
            except Exception:
                # best-effort fallback
                try:
                    os.remove(path)
                except Exception:
                    pass
                os.replace(tmp, path)

    def clear(self, tenant_id: str, provider: str) -> None:
        path = self._path(tenant_id, provider)
        with self._lock:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
