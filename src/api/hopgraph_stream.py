"""HopGraph streaming overlay (SSE) endpoint.

Provides a multi-tenant aware stream so the LIVE console and HopGraph Lite
pages can render supply-chain/binary/infrastructure overlays in near real time.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from collections import deque
from typing import Any, AsyncGenerator, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import StreamingResponse

try:
    from prometheus_client import Counter, Gauge  # type: ignore
    from src.api.metrics_init import ensure_metrics
except Exception:  # pragma: no cover - metrics optional in some test contexts
    Gauge = None  # type: ignore
    Counter = None  # type: ignore
    ensure_metrics = lambda: None  # type: ignore

from src.security.auth import AuthContext, require_api_key

router = APIRouter()

_CLIENTS: set[Tuple[asyncio.Queue, Optional[asyncio.AbstractEventLoop], Optional[str]]] = set()
_RECENT: deque[dict[str, Any]] = deque(maxlen=int(os.getenv('HOPGRAPH_STREAM_BACKLOG', '40') or 40))
_STREAM_LOOP: asyncio.AbstractEventLoop | None = None
_STREAM_PUBLISHED: Counter | None = None
_STREAM_CLIENTS: Gauge | None = None
_STREAM_QUEUE_DEPTH: Gauge | None = None


def _init_metrics() -> None:
    global _STREAM_PUBLISHED, _STREAM_CLIENTS, _STREAM_QUEUE_DEPTH
    if _STREAM_PUBLISHED is not None:
        return
    try:
        ensure_metrics()
        _STREAM_PUBLISHED = Counter('hopgraph_stream_events_total', 'HopGraph overlay events published')
        _STREAM_CLIENTS = Gauge('hopgraph_stream_clients', 'Connected HopGraph overlay SSE clients')
        _STREAM_QUEUE_DEPTH = Gauge('hopgraph_stream_queue_depth', 'HopGraph overlay SSE queue depth')
    except Exception:  # pragma: no cover - metrics optional
        _STREAM_PUBLISHED = None
        _STREAM_CLIENTS = None
        _STREAM_QUEUE_DEPTH = None


def _tenant_matches(event_tenant: Optional[str], client_tenant: Optional[str]) -> bool:
    if client_tenant is None or client_tenant == '':
        return True
    if event_tenant is None:
        return False
    return event_tenant == client_tenant


async def publish_hopgraph_overlay(event: dict[str, Any]) -> None:
    """Publish overlay snapshot to subscribed clients.

    Called from the HopGraph session builder once a session is saved.
    """
    _init_metrics()
    payload = dict(event)
    payload.setdefault('ts', time.time())
    try:
        _RECENT.append(payload)
    except Exception:
        pass

    for q, loop, tenant in list(_CLIENTS):
        if not _tenant_matches(payload.get('tenant'), tenant):
            continue
        try:
            if loop and getattr(loop, 'is_running', lambda: False)():
                try:
                    cur_loop = asyncio.get_running_loop()
                except RuntimeError:
                    cur_loop = None
                if loop is cur_loop:
                    q.put_nowait(payload)
                else:
                    asyncio.run_coroutine_threadsafe(q.put(payload), loop)
            else:
                q.put_nowait(payload)
        except Exception:
            continue

    if _STREAM_PUBLISHED:
        try:
            _STREAM_PUBLISHED.inc()
        except Exception:
            pass
    if _STREAM_QUEUE_DEPTH:
        try:
            depth = sum(getattr(q, 'qsize', lambda: 0)() for q, *_ in list(_CLIENTS))
            _STREAM_QUEUE_DEPTH.set(depth)
        except Exception:
            pass


async def publish_test_event(event: dict[str, Any]) -> None:
    """Deterministic test-mode publisher.

    When `HOPGRAPH_STREAM_TEST_MODE` is enabled, forward the event through
    the same pipeline as `publish_hopgraph_overlay`. Otherwise, act as a no-op
    to avoid affecting production behavior.
    """
    test_mode = os.getenv('HOPGRAPH_STREAM_TEST_MODE', '').lower() in {'1', 'true', 'yes'}
    if not test_mode:
        return
    await publish_hopgraph_overlay(event)


async def _event_stream(tenant_filter: Optional[str]) -> AsyncGenerator[bytes, None]:
    """Yield SSE chunks for a particular tenant filter."""
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    client_entry = (q, loop, tenant_filter)
    _CLIENTS.add(client_entry)
    if _STREAM_CLIENTS:
        try:
            _STREAM_CLIENTS.inc()
        except Exception:
            pass
    if loop and globals().get('_STREAM_LOOP') is None:
        globals()['_STREAM_LOOP'] = loop
    try:
        # Flush backlog that matches tenant scope
        for cached in list(_RECENT):
            if _tenant_matches(cached.get('tenant'), tenant_filter):
                data = json.dumps(cached, separators=(',', ':')).encode('utf-8')
                yield b'data: ' + data + b'\n\n'
        test_mode = os.getenv('HOPGRAPH_STREAM_TEST_MODE')
        if test_mode:
            sentinel = json.dumps({'status': 'test-mode'}).encode('utf-8')
            yield b'data: ' + sentinel + b'\n\n'
            return
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=10.0)
            except asyncio.TimeoutError:
                yield b':keepalive\n\n'
                continue
            data = json.dumps(item, separators=(',', ':')).encode('utf-8')
            yield b'data: ' + data + b'\n\n'
    finally:
        _CLIENTS.discard(client_entry)
        if _STREAM_CLIENTS:
            try:
                _STREAM_CLIENTS.dec()
            except Exception:
                pass
        if not _CLIENTS:
            globals()['_STREAM_LOOP'] = None


@router.get('/api/v1/graph/session/stream')  # type: ignore[misc]
async def hopgraph_stream(
    auth: AuthContext = Depends(require_api_key),
    x_tenant_id: Optional[str] = Header(default=None, alias='X-Tenant-Id'),
) -> StreamingResponse:
    """Exposes SSE stream for HopGraph overlay snapshots.

    API key enforcement is delegated to the platform auth dependency. Optional
    tenant scoping occurs through the X-Tenant-ID header; when omitted, events
    for all tenants are emitted (useful for single-tenant demo environments).
    """
    enforce_tenant = os.getenv('HOPGRAPH_STREAM_REQUIRE_TENANT', '0').lower() in {'1', 'true', 'yes'}
    tenant_filter = x_tenant_id.strip() if x_tenant_id else None
    if enforce_tenant and not tenant_filter:
        raise HTTPException(status_code=400, detail='tenant_required')

    async def wrap() -> AsyncGenerator[bytes, None]:
        try:
            async for chunk in _event_stream(tenant_filter):
                yield chunk
        except asyncio.CancelledError:
            raise

    return StreamingResponse(wrap(), media_type='text/event-stream')


__all__ = ['router', 'publish_hopgraph_overlay', 'publish_test_event']
