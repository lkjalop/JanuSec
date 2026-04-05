import time
import random
import email.utils
from datetime import datetime, timezone
from typing import Callable, Optional


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    # If it's integer seconds
    if value.isdigit():
        return float(int(value))
    # Otherwise try to parse an HTTP date
    try:
        tt = email.utils.parsedate_to_datetime(value)
        if tt.tzinfo is None:
            tt = tt.replace(tzinfo=timezone.utc)
        delta = (tt - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, delta)
    except Exception:
        return None


def _extract_retry_after_from_exception(e: Exception) -> (Optional[float], Optional[str]):
    # Return tuple (value, source) where source is 'attr' or 'header'
    # Prefer explicit attribute if set by a higher-level HTTP client
    if hasattr(e, "retry_after"):
        try:
            return float(getattr(e, "retry_after")), "attr"
        except Exception:
            pass
    # Some HTTP libraries attach a `response` with headers
    resp = getattr(e, "response", None)
    if resp is not None:
        # try case-insensitive headers
        headers = getattr(resp, "headers", None) or getattr(resp, "_headers", None) or {}
        # headers may be dict-like or a list
        if isinstance(headers, dict):
            for k, v in headers.items():
                if k.lower() == "retry-after":
                    return _parse_retry_after(v), "header"
        else:
            # try attribute access
            try:
                v = resp.headers.get("Retry-After")
                return _parse_retry_after(v), "header"
            except Exception:
                pass
    return None, None


def retry_with_backoff(fn: Callable, attempts: int = 3, base_sleep: float = 0.2, jitter: float = 0.1):
    """Retry `fn` up to `attempts` times.

    If an exception exposes a `retry_after` attribute or a `response.headers['Retry-After']`,
    that value will be honored (parsed as seconds or HTTP-date). Otherwise exponential
    backoff with jitter is used.
    """
    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:
            last_exc = e
            ra_value, ra_source = _extract_retry_after_from_exception(e)
            if ra_value is not None:
                # If retry_after was provided as an explicit exception attribute, honor
                # it exactly (used by some clients and sensitive tests). If the value
                # came from an HTTP header (parsed HTTP-date), enforce a small safety
                # minimum to avoid flakes due to clock and parsing jitter.
                sleep = float(ra_value)
                if ra_source == "header":
                    min_sleep = max(0.05, base_sleep * 5)
                    if sleep < min_sleep:
                        sleep = min_sleep
            else:
                sleep = base_sleep * (2 ** i) + random.uniform(0, jitter)
            time.sleep(sleep)
    raise last_exc
