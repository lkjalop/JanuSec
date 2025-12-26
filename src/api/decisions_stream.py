"""Server-Sent Events streaming of decisions."""
from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, AsyncGenerator
import logging

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

router: APIRouter = APIRouter()
# Per-client queues: each connected client gets its own asyncio.Queue created in that
# client's event loop. Store pairs (queue, loop) so producers running in other
# event loops or threads can schedule puts into the correct loop.
_CLIENT_QUEUES: set[tuple[asyncio.Queue, asyncio.AbstractEventLoop]] = set()
# Known SSE server event loop (set when the first client connects). Tests or
# auxiliary modules may inject different module objects; exposing the loop
# allows other code to schedule coroutines into the SSE loop via
# asyncio.run_coroutine_threadsafe.
_SSE_EVENT_LOOP: asyncio.AbstractEventLoop | None = None
from collections import deque

# Recently published decisions (small ring) flushed to new clients so they see
# decisions emitted just before they opened the stream (addresses race in tests)
_RECENT_DECISIONS: deque[dict[str, Any]] = deque(maxlen=50)

_TIMELINE_STORE: dict[str, dict[str, Any]] = {}
_TIMELINE_ORDER: deque[str] = deque(maxlen=500)  # remember insertion order for pruning
_TIMELINE_MAX = 500

# Metrics: use project-safe registration helpers and expose register_metrics
_SSE_PUBLISHED = None
_SSE_CLIENTS = None
_SSE_QUEUE_DEPTH = None

def register_metrics(registry: Any = None) -> None:
    """Explicitly bind SSE metrics to provided or shared registry."""
    global _SSE_PUBLISHED, _SSE_CLIENTS, _SSE_QUEUE_DEPTH
    try:
        from prometheus_client import Counter, Gauge

        from src.api.metrics_init import REGISTRY as DEFAULT_REG, ensure_metrics
        ensure_metrics()
        reg = registry or DEFAULT_REG
        _SSE_PUBLISHED = Counter('detection_sse_decisions_total','Total decisions published to SSE stream', registry=reg)
        _SSE_CLIENTS = Gauge('detection_sse_clients','Current connected SSE decision stream clients', registry=reg)
        _SSE_QUEUE_DEPTH = Gauge('detection_sse_queue_depth','Current internal SSE queue depth', registry=reg)
    except Exception:
        _SSE_PUBLISHED = _SSE_PUBLISHED or None
        _SSE_CLIENTS = _SSE_CLIENTS or None
        _SSE_QUEUE_DEPTH = _SSE_QUEUE_DEPTH or None

_LOG = logging.getLogger('decisions_stream')

async def publish_decision(summary: dict[str, Any]) -> None:
    """Publish decision to SSE clients and store compact stage timeline.

    Expected summary includes optional 'stage_timings' list of
    {name,duration_ms,confidence_after} items plus 'event_id'.
    """
    # Extract timeline and store for later retrieval endpoint
    eid = summary.get('event_id') or summary.get('id')
    st = summary.get('stage_timings') or []
    if eid and st:
        _TIMELINE_STORE[eid] = {
            'event_id': eid,
            'timeline': st,
            'factors': summary.get('factors', [])[:40],  # cap factors for memory
            'ts': summary.get('ts') or time.time(),
            'confidence': summary.get('confidence')
        }
        _TIMELINE_ORDER.append(eid)
        # Prune if exceeding cap
        if len(_TIMELINE_STORE) > _TIMELINE_MAX:
            try:
                old = _TIMELINE_ORDER.popleft()
                _TIMELINE_STORE.pop(old, None)
            except Exception:
                pass
    # Trim payload for SSE (avoid huge factor arrays)
    if 'factors' in summary and isinstance(summary['factors'], list) and len(summary['factors']) > 30:
        summary = dict(summary)
        summary['factors_truncated'] = summary['factors'][:30]
        del summary['factors']
    # Store in recent ring (copy lightweight)
    try:
        _RECENT_DECISIONS.append(summary)
    except Exception:
        pass
    if os.getenv('SSE_DEBUG'):
        try:
            eid = summary.get('event_id') or summary.get('id')
            try: print(f"[SSE_DEBUG] publish_decision called for {eid}; recent_ring_len={len(_RECENT_DECISIONS)}; clients={len(_CLIENT_QUEUES)}")
            except Exception: pass
        except Exception:
            pass
    # Broadcast to all connected client queues (best-effort, thread-safe).
    # AB test assignment: deterministically assign variants for active tests
    try:
        event_id = summary.get('event_id') or summary.get('id')
        if event_id:
            try:
                from src.repositories import ab_test_repo
                # list active tests
                active = await ab_test_repo.list_active()
                if active:
                    # For now, assign per-test using a hash of event_id
                    import hashlib
                    assigned = []
                    for t in active:
                        test_id = t.get('id')
                        # variants: for now read a comma-separated env var AB_TEST_{id}_VARIANTS or default ['A','B']
                        env_key = f'AB_TEST_{test_id}_VARIANTS'
                        variants = os.getenv(env_key)
                        if not variants:
                            variants_list = ['A','B']
                        else:
                            variants_list = [v.strip() for v in variants.split(',') if v.strip()]
                        if not variants_list:
                            variants_list = ['A','B']
                        h = hashlib.sha256(event_id.encode('utf-8')).hexdigest()
                        num = int(h[:8], 16)
                        variant = variants_list[num % len(variants_list)]
                        # persist assignment (best-effort)
                        try:
                            await ab_test_repo.assign_variant(test_id, None, event_id, variant)
                        except Exception:
                            pass
                        assigned.append({'test_id': test_id, 'variant': variant})
                    if assigned:
                        try:
                            summary = dict(summary)
                            summary['ab_tests'] = assigned
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception:
        pass
    try:
        # iterate over a snapshot to avoid modification during iteration
        for entry in list(_CLIENT_QUEUES):
            try:
                q, loop = entry
                # If we're in the same loop, put_nowait is fine and fast.
                try:
                    cur_loop = asyncio.get_event_loop()
                except Exception:
                    cur_loop = None
                if cur_loop is loop and getattr(loop, 'is_running', lambda: False)():
                    try:
                        q.put_nowait(summary)
                    except Exception:
                        # ignore full/closed queue
                        pass
                else:
                    # Different loop / thread: schedule a coroutine-safe put
                    try:
                        fut = asyncio.run_coroutine_threadsafe(q.put(summary), loop)
                        if os.getenv('SSE_DEBUG'):
                            try: print(f"[SSE_DEBUG] scheduled put to client loop {loop}; fut_done={fut.done()}")
                            except Exception: pass
                    except Exception:
                        # Fall back to best-effort put_nowait if scheduling fails
                        try:
                            q.put_nowait(summary)
                        except Exception:
                            pass
            except Exception:
                # ignore failures for individual clients
                continue
    except Exception:
        pass
    if _SSE_PUBLISHED:
        try: _SSE_PUBLISHED.inc()
        except Exception: pass
    if _SSE_QUEUE_DEPTH:
        try:
            depth = 0
            for entry in list(_CLIENT_QUEUES):
                try:
                    q, _ = entry
                    depth += getattr(q, 'qsize', lambda: 0)()
                except Exception:
                    pass
            _SSE_QUEUE_DEPTH.set(depth)
        except Exception:
            pass

async def _event_stream() -> AsyncGenerator[bytes, None]:
    # Only emit immediate sentinel in explicit SSE test mode; under normal pytest
    # execution we still want real streaming so tests can receive published decision.
    if os.getenv('SSE_TEST_MODE'):
        payload = json.dumps({'status': 'test-mode'}).encode('utf-8')
        yield b'data: ' + payload + b'\n\n'
        return

    # Each client creates its own queue so queue objects are tied to the
    # client's event loop and won't block across loops.
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    # register briefly to receive broadcasts along with its event loop
    try:
        loop = asyncio.get_event_loop()
    except Exception:
        loop = None
    client_entry = (q, loop)
    _CLIENT_QUEUES.add(client_entry)
    # Record the first observed SSE loop for cross-loop scheduling
    try:
        if loop is not None and globals().get('_SSE_EVENT_LOOP') is None:
            globals()['_SSE_EVENT_LOOP'] = loop
    except Exception:
        pass
    if os.getenv('SSE_DEBUG'):
        try: print(f"[SSE_DEBUG] client connected; total_clients={len(_CLIENT_QUEUES)}")
        except Exception: pass
    try:
        # Flush recent backlog first (unless in explicit test mode where sentinel
        # stands in for real data). To be robust against test-injected module
        # aliasing, gather recent entries from any module in sys.modules that
        # exposes a '_RECENT_DECISIONS' deque and yield those as backlog.
        if not os.getenv('SSE_TEST_MODE'):
            try:
                import sys as _sys
                seen = set()
                # prefer local ring first
                rings = []
                try:
                    if _RECENT_DECISIONS:
                        rings.append(_RECENT_DECISIONS)
                except Exception:
                    pass
                for m in list(_sys.modules.values()):
                    try:
                        rd = getattr(m, '_RECENT_DECISIONS', None)
                        if rd is not None and id(rd) not in seen:
                            rings.append(rd)
                            seen.add(id(rd))
                    except Exception:
                        continue
                for ring in rings:
                    for rec in list(ring):
                        try:
                            data = json.dumps(rec, separators=(',',':')).encode('utf-8')
                            yield b'data: ' + data + b'\n\n'
                        except Exception:
                            continue
            except Exception:
                # If anything goes wrong, fall back to local ring
                try:
                    for rec in list(_RECENT_DECISIONS):
                        try:
                            data = json.dumps(rec, separators=(',',':')).encode('utf-8')
                            yield b'data: ' + data + b'\n\n'
                        except Exception:
                            continue
                except Exception:
                    pass

        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=0.5)
            except asyncio.TimeoutError:
                if os.getenv('SSE_DEBUG'):
                    try: print(f"[SSE_DEBUG] yielding keepalive to client")
                    except Exception: pass
                yield b':keepalive\n\n'
                continue
            data = json.dumps(item, separators=(',',':')).encode('utf-8')
            yield b'data: ' + data + b'\n\n'
    finally:
        # remove client queue on disconnect
        try:
            _CLIENT_QUEUES.discard(client_entry)
            # If we removed the last client, clear the cached SSE loop
            try:
                if not _CLIENT_QUEUES:
                    globals()['_SSE_EVENT_LOOP'] = None
            except Exception:
                pass
            if os.getenv('SSE_DEBUG'):
                try: print(f"[SSE_DEBUG] client disconnected; total_clients={len(_CLIENT_QUEUES)}")
                except Exception: pass
        except Exception:
            pass

@router.get('/api/v1/stream/decisions')  # type: ignore[misc]
async def decisions_stream() -> StreamingResponse:
    if _SSE_CLIENTS:
        try: _SSE_CLIENTS.inc()
        except Exception: pass
    async def wrap() -> AsyncGenerator[bytes, None]:
        try:
            async for chunk in _event_stream():
                yield chunk
        finally:
            if _SSE_CLIENTS:
                try: _SSE_CLIENTS.dec()
                except Exception: pass
    return StreamingResponse(wrap(), media_type='text/event-stream')

# Alias to support legacy/frontend listener path
@router.get('/api/v1/stream/artifacts')  # type: ignore[misc]
async def artifacts_stream() -> StreamingResponse:  # pragma: no cover - thin alias
    async def wrap() -> AsyncGenerator[bytes, None]:
        async for chunk in _event_stream():
            yield chunk
    return StreamingResponse(wrap(), media_type='text/event-stream')

@router.get('/api/v1/decisions/timeline/{event_id}')  # type: ignore[misc]
async def decision_timeline(event_id: str) -> dict[str, Any]:
    """Return stored stage timeline (if still in memory window)."""
    item = _TIMELINE_STORE.get(event_id)
    if not item:
        return { 'found': False, 'event_id': event_id }
    return { 'found': True, 'timeline': item.get('timeline'), 'factors': item.get('factors'), 'confidence': item.get('confidence'), 'ts': item.get('ts') }

__all__ = ['router','publish_decision']
