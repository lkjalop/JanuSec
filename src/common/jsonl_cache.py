from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Tuple

_CACHE: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}


def get_jsonl(path: str, ttl: float = 60.0) -> List[Dict[str, Any]]:
    """Load a JSONL file into memory with a tiny TTL cache.

    Returns a list of dicts parsed from each non-empty line. On any error, returns [].
    """
    try:
        now = time.time()
        ts, data = _CACHE.get(path, (0.0, []))
        if ts and (now - ts) < max(1.0, float(ttl)):
            return data
        if not (path and os.path.exists(path)):
            _CACHE[path] = (now, [])
            return []
        items: List[Dict[str, Any]] = []
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                if isinstance(j, dict):
                    items.append(j)
        _CACHE[path] = (now, items)
        return items
    except Exception:
        _CACHE[path] = (time.time(), [])
        return []

__all__ = ["get_jsonl"]

