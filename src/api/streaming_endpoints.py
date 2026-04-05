from __future__ import annotations
import asyncio
import json
import logging
from typing import AsyncGenerator

from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from starlette.responses import StreamingResponse

from src.core.redis_helpers import get_redis_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/assessments', tags=['Streaming'])


def _ensure_broadcasters(app) -> dict:
    st = getattr(app.state, '_sse_broadcasters', None)
    if st is None:
        st = {}
        try:
            app.state._sse_broadcasters = st
        except Exception:
            pass
    return st


@router.get('/{assessment_id}/events')
async def sse_events(request: Request, assessment_id: str):
    """Server-Sent Events endpoint streaming partial results for an assessment."""
    app = request.app
    channel = f"assessment:events:{assessment_id}"
    q: asyncio.Queue = asyncio.Queue()

    broadcasters = _ensure_broadcasters(app)
    listeners = broadcasters.get(channel) or []
    listeners.append(lambda msg: q.put_nowait(msg))
    broadcasters[channel] = listeners

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(q.get(), timeout=5.0)
                except asyncio.TimeoutError:
                    # heartbeat
                    yield 'event: ping\n\n'
                    continue
                try:
                    data = json.dumps(payload)
                except Exception:
                    data = str(payload)
                yield f"data: {data}\n\n"
        finally:
            # remove listener
            try:
                listeners = broadcasters.get(channel) or []
                listeners = [cb for cb in listeners if cb is not (lambda msg: q.put_nowait(msg))]
                broadcasters[channel] = listeners
            except Exception:
                pass

    return StreamingResponse(event_generator(), media_type='text/event-stream')


@router.websocket('/{assessment_id}/ws')
async def ws_events(websocket: WebSocket, assessment_id: str):
    await websocket.accept()
    channel = f"assessment:events:{assessment_id}"
    q: asyncio.Queue = asyncio.Queue()
    app = websocket.app
    broadcasters = _ensure_broadcasters(app)
    listeners = broadcasters.get(channel) or []
    listeners.append(lambda msg: q.put_nowait(msg))
    broadcasters[channel] = listeners
    try:
        while True:
            try:
                payload = await asyncio.wait_for(q.get(), timeout=5.0)
                try:
                    await websocket.send_text(json.dumps(payload))
                except Exception:
                    await websocket.send_text(str(payload))
            except asyncio.TimeoutError:
                # ping to keep connection alive
                try:
                    await websocket.send_text(json.dumps({'type': 'ping'}))
                except Exception:
                    pass
            # allow client messages (no-op) to detect disconnects
            try:
                if websocket.client_state.name != 'CONNECTED':
                    break
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        try:
            listeners = broadcasters.get(channel) or []
            listeners = [cb for cb in listeners if cb is not (lambda msg: q.put_nowait(msg))]
            broadcasters[channel] = listeners
        except Exception:
            pass
