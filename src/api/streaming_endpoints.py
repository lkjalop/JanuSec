from __future__ import annotations
import asyncio
import json
import logging
import os
import time
import uuid
from typing import AsyncGenerator, Any, Dict, List, Optional

from fastapi import Depends, APIRouter, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from src.security.auth import auth_dependency
from src.api.tenant_helpers import resolve_tenant_id
from pydantic import BaseModel, Field
from starlette.responses import StreamingResponse

try:
    from src.core.redis_helpers import get_redis_client
except Exception:
    get_redis_client = None  # type: ignore

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/assessments', tags=['Streaming'])

# ── Streaming ingest sub-router (mounted separately under /api/v1/stream) ─────
_ingest_router = APIRouter(prefix='/api/v1/stream', tags=['Streaming Ingest'])

MAX_ROWS_PER_CALL = 5000


async def _stream_auth(
    x_api_key: str | None = Header(None), authorization: str | None = Header(None),
):
    return await auth_dependency(x_api_key, authorization, None)


class _CreateSessionReq(BaseModel):
    org: Optional[str] = None
    assessment_id: Optional[str] = None


class _IngestReq(BaseModel):
    rows: List[Dict[str, Any]] = Field(default_factory=list)
    source: Optional[str] = None


def _check_auth(x_api_key: Optional[str]) -> None:
    if os.getenv('JANUSEC_DEV_MODE') or os.getenv('TEST_HELPERS_ENABLED'):
        return
    expected = os.getenv('JANUSEC_API_KEY') or os.getenv('API_KEY') or 'devkey123'
    if not x_api_key or x_api_key != expected:
        raise HTTPException(status_code=401, detail='Invalid API key')


def _require_session(assessment_id: str, tenant_id: str):
    try:
        from src.pipeline.streaming_ingest import get_session
    except ImportError:
        try:
            from pipeline.streaming_ingest import get_session  # type: ignore
        except ImportError:
            raise HTTPException(status_code=503, detail='streaming_ingest module unavailable')
    session = get_session(assessment_id)
    if session is None or getattr(session, "org", None) != tenant_id:
        raise HTTPException(status_code=404, detail=f'Stream session {assessment_id!r} not found. Create it first via POST /api/v1/stream/sessions')
    return session


@_ingest_router.post('/sessions', status_code=201)
async def create_stream_session(
    body: _CreateSessionReq,
    request: Request,
    auth: Any = Depends(_stream_auth),
) -> JSONResponse:
    """Create a new streaming assessment session.

    Returns assessment_id to use for subsequent /ingest, /snapshot, and /close calls.
    """
    tenant_id = resolve_tenant_id(request, auth=auth)
    try:
        from src.pipeline.streaming_ingest import get_or_create_session
    except ImportError:
        from pipeline.streaming_ingest import get_or_create_session  # type: ignore

    tenant_id = resolve_tenant_id(request, body.org, auth=auth)
    from src.pipeline.streaming_ingest import get_session
    if body.assessment_id and get_session(body.assessment_id) is not None:
        _require_session(body.assessment_id, tenant_id)
    assessment_id = body.assessment_id or f'stream-{int(time.time())}-{uuid.uuid4().hex[:8]}'
    from src.core.assessment_run import register_json_entry_safe
    run = await register_json_entry_safe(
        tenant_id=tenant_id, case_id=assessment_id, entry_kind="stream",
        source="stream_session", source_native_id=assessment_id,
        document={"assessment_id": assessment_id, "org": tenant_id},
    )
    session = get_or_create_session(assessment_id, org=tenant_id)
    _require_session(assessment_id, tenant_id)
    return JSONResponse({'assessment_id': assessment_id, 'status': 'streaming', 'org': tenant_id, 'assessment_run': run}, status_code=201)


@_ingest_router.post('/sessions/{assessment_id}/ingest')
async def ingest_stream_rows(
    assessment_id: str,
    body: _IngestReq,
    request: Request,
    auth: Any = Depends(_stream_auth),
) -> JSONResponse:
    """Push a batch of raw events from one source connector.

    Callers should chunk 44k-row datasets into ≤500-row batches.
    Source names: cloudtrail, azure_signin, okta, exchange, zeek, crowdstrike, vpn, etc.
    """
    tenant_id = resolve_tenant_id(request, auth=auth)
    session = _require_session(assessment_id, tenant_id)
    rows = body.rows[:MAX_ROWS_PER_CALL]
    if not rows:
        return JSONResponse({'accepted': 0, 'deduped': 0, 'circuit_dropped': 0, 'cluster_count': 0})
    from src.core.assessment_run import register_json_entry_safe
    run = await register_json_entry_safe(
        tenant_id=str(getattr(session, "org", None) or "default"), case_id=assessment_id,
        entry_kind="stream_batch", source=body.source or "stream",
        source_native_id=f"{assessment_id}:{time.time_ns()}", document={"rows": rows, "source": body.source},
    )
    try:
        result = await session.ingest(rows, source=body.source)
    except Exception as exc:
        logger.warning('stream ingest error %s: %s', assessment_id, exc)
        raise HTTPException(status_code=500, detail=str(exc))
    snap = session.snapshot()
    return JSONResponse({**result, 'cluster_count': snap['cluster_count'], 'total_ingested': snap['total_ingested'], 'assessment_run': run})


@_ingest_router.get('/sessions/{assessment_id}/snapshot')
async def get_stream_snapshot(
    assessment_id: str,
    request: Request,
    auth: Any = Depends(_stream_auth),
) -> JSONResponse:
    """Poll current cluster state without waiting for completion."""
    tenant_id = resolve_tenant_id(request, auth=auth)
    return JSONResponse(_require_session(assessment_id, tenant_id).snapshot())


@_ingest_router.post('/sessions/{assessment_id}/close')
async def close_stream_session(
    assessment_id: str,
    request: Request,
    auth: Any = Depends(_stream_auth),
) -> JSONResponse:
    """Finalize, run last prefill, persist. After this call the session is in REPORT_STORE."""
    tenant_id = resolve_tenant_id(request, auth=auth)
    session = _require_session(assessment_id, tenant_id)
    result = await session.close()
    try:
        from src.api.deep_analyze_endpoints import REPORT_STORE, _persist_assessment_state
        REPORT_STORE[assessment_id] = session._assessment_obj
        _persist_assessment_state(assessment_id, session._assessment_obj)
    except Exception as exc:
        logger.debug('stream close: REPORT_STORE persist failed: %s', exc)
    try:
        from src.pipeline.streaming_ingest import close_session
        close_session(assessment_id)
    except Exception:
        pass
    return JSONResponse(result)


@_ingest_router.delete('/sessions/{assessment_id}')
async def discard_stream_session(
    assessment_id: str,
    x_api_key: Optional[str] = Header(None, alias='X-API-Key'),
) -> JSONResponse:
    """Discard a streaming session without persisting."""
    _check_auth(x_api_key)
    try:
        from src.pipeline.streaming_ingest import close_session
        close_session(assessment_id)
    except Exception:
        pass
    return JSONResponse({'assessment_id': assessment_id, 'status': 'discarded'})


# Expose the ingest sub-router so app.py can include it
ingest_router = _ingest_router


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
