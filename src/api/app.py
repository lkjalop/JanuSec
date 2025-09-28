
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import defaultdict, deque
from typing import List, Awaitable, Callable

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.responses import Response

from .routes import events, internal, metrics, hunt_lanes
from .decisions_stream import router as decisions_router
from .metrics_init import ensure_metrics, REGISTRY

try:  # pragma: no cover - optional dependency
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest  # type: ignore
except Exception:  # pragma: no cover
    CONTENT_TYPE_LATEST = 'text/plain; version=0.0.4; charset=utf-8'
    generate_latest = None  # type: ignore

app = FastAPI(title='Threat Platform API', version='4.1.0')

logger = logging.getLogger(__name__)

try:
    ensure_metrics()
except Exception as exc:  # pragma: no cover - metrics optional in some envs
    logger.warning('Prometheus metrics initialization failed: %s', exc)

_RATE_LIMIT_ENABLED = os.getenv('RATE_LIMIT_ENABLED', '1').lower() not in {'0', 'false', 'no'}
_RATE_LIMIT_MAX_REQUESTS = int(os.getenv('RATE_LIMIT_MAX_REQUESTS', '300'))
_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv('RATE_LIMIT_WINDOW_SECONDS', '60'))
_RATE_LIMIT_STORAGE: defaultdict[str, deque[float]] = defaultdict(deque)
_RATE_LIMIT_LOCK = asyncio.Lock()

_ALLOWED_ORIGINS: List[str] = [origin.strip() for origin in os.getenv('ALLOWED_ORIGINS', '').split(',') if origin.strip()]
if not _ALLOWED_ORIGINS:
    _ALLOWED_ORIGINS = ['https://localhost']

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allow_headers=['Authorization', 'Content-Type', 'X-Tenant-Id', 'X-Requested-With'],
    expose_headers=['X-Request-ID'],
)

if os.getenv('HTTPS_REDIRECT_ENABLED', '0').lower() not in {'0', 'false', 'no'}:
    app.add_middleware(HTTPSRedirectMiddleware)


@app.middleware('http')
async def _rate_limit_requests(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    if not _RATE_LIMIT_ENABLED or _RATE_LIMIT_MAX_REQUESTS <= 0 or _RATE_LIMIT_WINDOW_SECONDS <= 0:
        return await call_next(request)
    client_ip = request.client.host if request.client else 'unknown'
    now = time.monotonic()
    async with _RATE_LIMIT_LOCK:
        window = _RATE_LIMIT_STORAGE[client_ip]
        cutoff = now - _RATE_LIMIT_WINDOW_SECONDS
        while window and window[0] <= cutoff:
            window.popleft()
        if len(window) >= _RATE_LIMIT_MAX_REQUESTS:
            return Response(status_code=429, content=json.dumps({'detail': 'rate_limit_exceeded'}), media_type='application/json')
        window.append(now)
    return await call_next(request)


@app.middleware('http')
async def _add_security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    response = await call_next(request)
    response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    response.headers.setdefault('Content-Security-Policy', "default-src 'self'")
    return response


app.include_router(events.router)
app.include_router(metrics.router)
app.include_router(internal.router)
app.include_router(hunt_lanes.router)
app.include_router(decisions_router)

@app.get('/metrics', include_in_schema=False)
async def metrics_endpoint() -> Response:
    if generate_latest is None or REGISTRY is None:
        raise HTTPException(status_code=503, detail='metrics_not_available')
    try:
        ensure_metrics()
    except Exception as exc:  # pragma: no cover
        logger.debug('ensure_metrics failed during scrape: %s', exc)
    payload = generate_latest(REGISTRY)
    return Response(content=payload, media_type=CONTENT_TYPE_LATEST)

__all__ = ['app']
