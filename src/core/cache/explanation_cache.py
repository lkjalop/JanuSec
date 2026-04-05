from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional


class ExplanationCache:
    """Simple file-backed explanation cache with TTL and generator metadata.

    Keying is by a stable string (e.g. decision_id or session_explain_key).
    Stored entries contain: { 'key', 'ts', 'ttl', 'payload', 'meta' }
    """

    def __init__(self, persist_dir: Optional[str] = None):
        # prefer explicit override, then SESSION_PERSIST_DIR, then default
        default_dir = os.getenv('SESSION_PERSIST_DIR') or os.getenv('EXPLANATION_CACHE_DIR') or 'data/explain_cache'
        self.dir = Path(persist_dir or default_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = key.replace('/', '_').replace(':', '_')
        return self.dir / f"explain_{safe}.json"

    def set(self, key: str, payload: Dict[str, Any], ttl: int = 3600, meta: Optional[Dict[str, Any]] = None) -> None:
        obj = {
            'key': key,
            'ts': time.time(),
            'ttl': int(ttl),
            'payload': payload,
            'meta': meta or {}
        }
        p = self._path(key)
        try:
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(obj, f, ensure_ascii=False)
        except Exception:
            # best-effort
            pass

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        p = self._path(key)
        try:
            if not p.exists():
                return None
            with open(p, 'r', encoding='utf-8') as f:
                obj = json.load(f)
            ts = float(obj.get('ts', 0) or 0)
            ttl = int(obj.get('ttl', 0) or 0)
            if ttl > 0 and (time.time() - ts) > ttl:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
                return None
            return obj
        except Exception:
            return None

    def purge_expired(self) -> None:
        try:
            now = time.time()
            for f in self.dir.glob('explain_*.json'):
                try:
                    with open(f, 'r', encoding='utf-8') as fh:
                        o = json.load(fh)
                    ts = float(o.get('ts', 0) or 0)
                    ttl = int(o.get('ttl', 0) or 0)
                    if ttl > 0 and (now - ts) > ttl:
                        f.unlink(missing_ok=True)
                except Exception:
                    continue
        except Exception:
            pass


__all__ = ['ExplanationCache']
