from __future__ import annotations

import time
import os
from typing import Optional

_CACHE: dict = {}
_TTL = int(os.getenv('JWKS_CACHE_TTL', '300'))


def get_jwks(issuer: str) -> Optional[dict]:
    now = time.time()
    key = issuer.rstrip('/') + '/.well-known/jwks.json'
    cached = _CACHE.get(key)
    if cached and (now - cached.get('ts', 0)) < _TTL:
        return cached.get('jwks')
    # Lazy import to keep optional deps optional
    try:
        import httpx
        r = httpx.get(key, timeout=5.0)
        jwks = r.json()
        _CACHE[key] = {'jwks': jwks, 'ts': now}
        return jwks
    except Exception:
        return None
