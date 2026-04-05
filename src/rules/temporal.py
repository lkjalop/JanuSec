from __future__ import annotations

import time
from typing import List, Dict, Any


def within_window(events: List[Dict[str, Any]], field: str, value: Any, window_seconds: int) -> int:
    """Return count of events within the last `window_seconds` seconds where event[field]==value."""
    now = time.time()
    cnt = 0
    for ev in events:
        try:
            ts = float(ev.get('ts') or ev.get('timestamp') or now)
        except Exception:
            ts = now
        if (now - ts) <= float(window_seconds):
            try:
                if ev.get(field) == value:
                    cnt += 1
            except Exception:
                continue
    return cnt


__all__ = ['within_window']
