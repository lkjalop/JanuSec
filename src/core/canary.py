import hashlib
from typing import Any


def pick_by_event(event_id: str, pct: float) -> bool:
    """Deterministic selection: hash event_id and pick if modulo 100 < pct"""
    try:
        h = hashlib.sha256(event_id.encode('utf-8')).digest()
        # use first two bytes to get a number 0-65535
        v = (h[0] << 8) + h[1]
        return (v % 100) < int(pct)
    except Exception:
        return False
