"""Authentication & rate limiting dependency for alert endpoints."""
from __future__ import annotations

import asyncio
import os
import time

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader

_RAW_ALERT_KEYS = os.getenv('ALERTS_API_KEYS','')
ALERT_API_KEYS = {k.strip(): True for k in _RAW_ALERT_KEYS.split(',') if k.strip()}
ALERTS_REQUIRE_AUTH = bool(ALERT_API_KEYS)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

RATE_LIMIT_RPS = float(os.getenv('ALERTS_RL_RPS','5'))
RATE_LIMIT_BURST = float(os.getenv('ALERTS_RL_BURST','10'))
_RL: dict[str, dict[str,float]] = {}
_RL_LOCK = asyncio.Lock()

async def alerts_auth(request: Request, api_key: str | None = Security(_api_key_header)):
    if ALERTS_REQUIRE_AUTH:
        if not api_key or api_key not in ALERT_API_KEYS:
            raise HTTPException(status_code=401, detail='unauthorized')
        ident = f"key:{api_key[:8]}"
    else:
        client_ip = request.client.host if request and request.client else 'anon'
        ident = f"ip:{client_ip}"
    # Token bucket
    now = time.time()
    async with _RL_LOCK:
        st = _RL.get(ident)
        if not st:
            st = {'tokens': RATE_LIMIT_BURST, 'ts': now}
            _RL[ident] = st
        elapsed = now - st['ts']
        if elapsed > 0:
            refill = elapsed * RATE_LIMIT_RPS
            st['tokens'] = min(RATE_LIMIT_BURST, st['tokens'] + refill)
            st['ts'] = now
        if st['tokens'] < 1:
            raise HTTPException(status_code=429, detail='rate_limited')
        st['tokens'] -= 1
    return ident

__all__ = ['alerts_auth','ALERTS_REQUIRE_AUTH']
