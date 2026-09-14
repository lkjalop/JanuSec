"""Parse source event time without substituting processing time."""
from datetime import datetime, timezone
import math


def event_epoch(value) -> float | None:
    if value is None or value == "" or isinstance(value, bool):
        return None
    try:
        ts = float(value)
        if not math.isfinite(ts):
            return None
        return ts / 1000 if abs(ts) >= 1e12 else ts
    except (ValueError, TypeError):
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except (ValueError, TypeError, OverflowError):
            return None
