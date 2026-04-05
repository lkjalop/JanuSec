import hmac
import hashlib
import time
from typing import Optional

REPLAY_WINDOW_SEC = 300

def verify_hmac_signature(body: bytes, signature: str, secret: str, algo: str = "sha256") -> bool:
    digestmod = getattr(hashlib, algo)
    computed = hmac.new(secret.encode("utf-8"), body, digestmod).hexdigest()
    return hmac.compare_digest(computed, signature)

def within_replay_window(ts: int, now: Optional[int] = None) -> bool:
    now = now or int(time.time())
    return abs(now - ts) <= REPLAY_WINDOW_SEC
