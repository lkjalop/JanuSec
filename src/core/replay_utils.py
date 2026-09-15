import hashlib
import hmac
import base64
from typing import Optional


def fingerprint_bytes(data: bytes) -> str:
    """Return a hex fingerprint of the payload for idempotency checks."""
    return hashlib.sha256(data).hexdigest()


def compute_hmac_sha256(key: bytes, data: bytes) -> str:
    mac = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(mac).decode('ascii')


def constant_time_compare(a: str, b: str) -> bool:
    try:
        return hmac.compare_digest(a, b)
    except Exception:
        return False
