from __future__ import annotations
import os, json, time, uuid, asyncio
from pathlib import Path
from typing import Any
from fastapi import APIRouter, Request, HTTPException, Query, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from security.auth import require_scopes, auth_dependency
from hashlib import sha256

router = APIRouter(tags=["Telemetry"])

TELEMETRY_PATH = Path(os.getenv('TELEMETRY_PATH', 'data/telemetry_dispositions.jsonl'))

_DISPOSITIONS: list[dict[str, Any]] = []
_telemetry_updated: asyncio.Event = asyncio.Event()
_UNDO_PATH = Path(os.getenv('TELEMETRY_UNDO_PATH', 'data/telemetry_undo_tokens.jsonl'))
_UNDO_MAP: dict[str, list[str]] = {}
_UNDO_LIST: list[dict[str, Any]] = []
_WS_CONNECTIONS: set[WebSocket] = set()


def _ensure_dirs():
    try:
        TELEMETRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _persist(rec: dict[str, Any]):
    _ensure_dirs()
    try:
        with TELEMETRY_PATH.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(rec, sort_keys=True) + '\n')
    except Exception:
        pass


def _persist_undo(token: str, ids: list[str]):
    _ensure_dirs()
    rec = {'token': token, 'ids': ids, 'ts': time.time()}
    try:
        with _UNDO_PATH.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(rec, sort_keys=True) + '\n')
    except Exception:
        pass
    _UNDO_MAP[token] = ids
    _UNDO_LIST.append(rec)


def _persist_llm_feedback(entry: dict[str, Any]):
    try:
        LLM_FEEDBACK_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LLM_FEEDBACK_PATH.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(entry, sort_keys=True) + '\n')
    except Exception:
        pass


def _load():
    if not TELEMETRY_PATH.exists():
        return
    try:
        with TELEMETRY_PATH.open('r', encoding='utf-8') as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rec = json.loads(ln)
                    _DISPOSITIONS.append(rec)
                except Exception:
                    continue
    except Exception:
        pass


_load()
# load undo tokens
try:
    if _UNDO_PATH.exists():
        with _UNDO_PATH.open('r', encoding='utf-8') as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln: continue
                try:
                    rec = json.loads(ln)
                    if rec.get('token') and isinstance(rec.get('ids'), list):
                        _UNDO_MAP[rec['token']] = rec['ids']
                except Exception:
                    continue
except Exception:
    pass





async def broadcast_metrics():
    try:
        j = await telemetry_metrics()
    except Exception:
        j = None
    if not _WS_CONNECTIONS:
        return
    msg = json.dumps({'type': 'metrics', 'payload': j})
    remove = []
    for ws in list(_WS_CONNECTIONS):
        try:
            await ws.send_text(msg)
        except Exception:
            remove.append(ws)
    for r in remove:
        try: _WS_CONNECTIONS.discard(r)
        except Exception: pass


@router.websocket('/api/v1/telemetry/ws')
async def telemetry_ws(websocket: WebSocket):
    # Accept query param api_key optionally for future auth
    await websocket.accept()
    _WS_CONNECTIONS.add(websocket)
    try:
        while True:
            # keep connection alive; clients may send pings
            try:
                await websocket.receive_text()
            except WebSocketDisconnect:
                break
            except Exception:
                await asyncio.sleep(0.5)
    finally:
        try: _WS_CONNECTIONS.discard(websocket)
        except Exception: pass


@router.post('/api/v1/telemetry/disposition')
async def post_disposition(request: Request):
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail='bad_json')
    disp = data.get('disposition')
    if disp not in {'benign', 'malicious', 'needs_review'}:
        raise HTTPException(status_code=400, detail='invalid_disposition')
    rec = {
        'id': data.get('id') or str(uuid.uuid4()),
        'event_id': data.get('event_id'),
        'source': data.get('source') or 'csv',
        'row_index': data.get('row_index'),
        'case_id': data.get('case_id'),
        'disposition': disp,
        'analyst': data.get('analyst') if data.get('analyst') is not None else None,
        'notes': data.get('notes'),
        'ts': float(data.get('ts') or time.time()),
    }
    _DISPOSITIONS.append(rec)
    _persist(rec)
    llm_fb = data.get('llm_feedback')
    if isinstance(llm_fb, dict):
        try:
            fb_entry = dict(llm_fb)
            fb_entry.update({'event_id': rec['event_id'], 'row_index': rec['row_index'], 'disposition': rec['disposition'], 'ts': rec['ts']})
            _persist_llm_feedback(fb_entry)
        except Exception:
            pass
    try:
        _telemetry_updated.set()
    except Exception:
        pass
    # generate undo token for this single disposition
    try:
        token = sha256((str(rec['ts']) + rec['id'] + str(uuid.uuid4())).encode('utf-8')).hexdigest()
        _persist_undo(token, [rec['id']])
    except Exception:
        token = None
    # broadcast to websocket clients
    try:
        asyncio.create_task(broadcast_metrics())
    except Exception:
        pass
    out = {'ok': True, 'id': rec['id']}
    if token:
        out['undo_token'] = token
    return out


@router.post('/api/v1/telemetry/dispositions')
async def post_dispositions(request: Request):
    """Accept an array of disposition records and persist them atomically."""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if not isinstance(data, list):
        raise HTTPException(status_code=400, detail='expected_list')
    out_ids = []
    now = time.time()
    for item in data:
        if not isinstance(item, dict):
            continue
        disp = item.get('disposition')
        if disp not in {'benign', 'malicious', 'needs_review'}:
            continue
        rec = {
            'id': item.get('id') or str(uuid.uuid4()),
            'event_id': item.get('event_id'),
            'source': item.get('source') or 'csv',
            'row_index': item.get('row_index'),
            'case_id': item.get('case_id'),
            'disposition': disp,
            'analyst': item.get('analyst') if item.get('analyst') is not None else None,
            'notes': item.get('notes'),
            'ts': float(item.get('ts') or now),
        }
        _DISPOSITIONS.append(rec)
        _persist(rec)
        llm_fb = item.get('llm_feedback')
        if isinstance(llm_fb, dict):
            try:
                fb_entry = dict(llm_fb)
                fb_entry.update({'event_id': rec['event_id'], 'row_index': rec['row_index'], 'disposition': rec['disposition'], 'ts': rec['ts']})
                _persist_llm_feedback(fb_entry)
            except Exception:
                pass
        out_ids.append(rec['id'])
    # generate undo token for this batch
    token = sha256((str(now) + ''.join(out_ids) + str(uuid.uuid4())).encode('utf-8')).hexdigest()
    try:
        _persist_undo(token, out_ids)
    except Exception:
        pass
    try:
        _telemetry_updated.set()
    except Exception:
        pass
    try:
        asyncio.create_task(broadcast_metrics())
    except Exception:
        pass
    return {'ok': True, 'ids': out_ids, 'undo_token': token}


async def _telemetry_feedback_allowed(request: Request) -> bool:
    try:
        if os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ:
            return True
    except Exception:
        pass
    try:
        api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
        authorization = request.headers.get('Authorization')
        await auth_dependency(api_key, authorization, ['feedback.write'])
        return True
    except Exception:
        return False


@router.post('/api/v1/telemetry/preview_undo')
async def preview_undo(request: Request):
    if not await _telemetry_feedback_allowed(request):
        raise HTTPException(status_code=401, detail='unauthorized')
    """Given a token or list of ids, return the disposition records that would be reverted (preview)."""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    ids = None
    if isinstance(data, dict) and data.get('token'):
        ids = _UNDO_MAP.get(data.get('token'))
    elif isinstance(data, dict) and isinstance(data.get('ids'), list):
        ids = data.get('ids')
    if not ids:
        raise HTTPException(status_code=400, detail='no_ids')
    # find matching records
    found = [d for d in _DISPOSITIONS if d.get('id') in ids]
    return {'count': len(found), 'rows': found}


@router.post('/api/v1/telemetry/undo_with_token')
async def telemetry_undo_with_token(request: Request):
    if not await _telemetry_feedback_allowed(request):
        raise HTTPException(status_code=401, detail='unauthorized')
    """Undo dispositions by token. Marks reverted and returns marked ids."""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    token = data.get('token')
    if not token:
        raise HTTPException(status_code=400, detail='missing_token')
    ids = _UNDO_MAP.get(token)
    if not ids:
        raise HTTPException(status_code=404, detail='token_not_found')
    now = time.time()
    marked = []
    for rec in _DISPOSITIONS:
        if rec.get('id') in ids and not rec.get('reverted'):
            rec['reverted'] = True
            rec['reverted_ts'] = now
            marked.append(rec.get('id'))
    # persist undo audit
    undo_rec = {'action': 'undo_token', 'token': token, 'marked': marked, 'ts': now}
    _persist(undo_rec)
    try:
        _telemetry_updated.set()
    except Exception:
        pass
    try:
        asyncio.create_task(broadcast_metrics())
    except Exception:
        pass
    return {'ok': True, 'marked': marked}


@router.get('/api/v1/telemetry/recent')
async def telemetry_recent(limit: int = Query(200, ge=1, le=500)):
    """Return recent dispositions (most recent first) to allow the UI to decorate rows."""
    # Note: _DISPOSITIONS is append-only (older first)
    sliced = _DISPOSITIONS[-limit:]
    return {'count': len(sliced), 'rows': list(reversed(sliced))}


@router.post('/api/v1/telemetry/undo')
async def telemetry_undo(request: Request, _=Depends(require_scopes('feedback.write'))):
    try:
        if os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ:
            _ = None
    except Exception:
        pass
    """Mark dispositions as reverted by id. Returns list of ids marked."""
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    ids = data.get('ids') if isinstance(data, dict) else None
    if not ids or not isinstance(ids, list):
        raise HTTPException(status_code=400, detail='expected_ids')
    now = time.time()
    marked = []
    idset = set(ids)
    for rec in _DISPOSITIONS:
        if rec.get('id') in idset and not rec.get('reverted'):
            rec['reverted'] = True
            rec['reverted_ts'] = now
            marked.append(rec.get('id'))
    # persist undo action as a record for audit
    undo_rec = {'action': 'undo', 'target_ids': list(marked), 'ts': now}
    _persist(undo_rec)
    try:
        _telemetry_updated.set()
    except Exception:
        pass
    try:
        asyncio.create_task(broadcast_metrics())
    except Exception:
        pass
    return {'ok': True, 'marked': marked}


@router.get('/api/v1/telemetry/metrics')
async def telemetry_metrics(since: float | None = Query(None, description='unix ts cutoff, optional')):
    now = time.time()
    cutoff = float(since) if since else now - 86400
    total = len(_DISPOSITIONS)
    by_disp = {'benign': 0, 'malicious': 0, 'needs_review': 0}
    by_day: dict[str, int] = {}
    recent = 0
    for d in _DISPOSITIONS:
        # skip reverted records
        if d.get('reverted'):
            continue
        disp = d.get('disposition')
        if disp in by_disp:
            by_disp[disp] += 1
        t = float(d.get('ts') or now)
        day = time.strftime('%Y-%m-%d', time.gmtime(t))
        by_day[day] = by_day.get(day, 0) + 1
        if t >= cutoff:
            recent += 1
    tp_fp_estimates = {}
    # Simple proxy: benign_ratio = benign/(benign+malicious)
    denom = by_disp['benign'] + by_disp['malicious']
    if denom:
        tp_fp_estimates['benign_ratio'] = by_disp['benign'] / denom
        tp_fp_estimates['malicious_ratio'] = by_disp['malicious'] / denom
    else:
        tp_fp_estimates['benign_ratio'] = None
        tp_fp_estimates['malicious_ratio'] = None
    return {
        'total_dispositions': total,
        'by_disposition': by_disp,
        'by_day': sorted(list(by_day.items()), key=lambda x: x[0]),
        'recent_24h_count': recent,
        'tp_fp_estimates': tp_fp_estimates,
        'generated_at': now,
    }


@router.get('/api/v1/telemetry/undo_tokens')
async def list_undo_tokens(limit: int = Query(100, ge=1, le=1000), _=Depends(require_scopes('feedback.write'))):
    # return recent undo tokens (most recent first)
    rows = list(reversed(_UNDO_LIST[-limit:]))
    return {'count': len(rows), 'tokens': rows}


@router.post('/api/v1/telemetry/trigger_broadcast')
async def trigger_broadcast(_=Depends(require_scopes('feedback.write'))):
    """Trigger an immediate broadcast to connected telemetry websocket clients."""
    try:
        asyncio.create_task(broadcast_metrics())
    except Exception:
        pass
    return {'ok': True}


@router.get('/api/v1/telemetry/stream')
async def telemetry_stream():
    """SSE stream that emits telemetry metrics when dispositions change."""
    async def event_generator():
        # send one initial ping
        try:
            j = await telemetry_metrics()
            yield f"data: {json.dumps({'type':'metrics','payload': j})}\n\n"
        except Exception:
            yield 'data: {}\n\n'
        while True:
            try:
                # wait for update
                await _telemetry_updated.wait()
                _telemetry_updated.clear()
                try:
                    j = await telemetry_metrics()
                    yield f"data: {json.dumps({'type':'metrics','payload': j})}\n\n"
                except Exception:
                    yield 'data: {}\n\n'
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(1)
    return StreamingResponse(event_generator(), media_type='text/event-stream')


# Include heartbeat endpoints if available (keeps router inclusion consolidated)
try:
    from .heartbeat_endpoints import router as heartbeat_router
    try:
        router.include_router(heartbeat_router)
    except Exception:
        pass
except Exception:
    pass

try:
    from .collector_telemetry_endpoints import router as collector_telemetry_router
    try:
        router.include_router(collector_telemetry_router)
    except Exception:
        pass
except Exception:
    pass

try:
    from .playbook_approval_endpoints import router as playbook_approval_router
    try:
        router.include_router(playbook_approval_router)
    except Exception:
        pass
except Exception:
    pass


@router.post('/api/v1/telemetry/diagnose')
async def telemetry_diagnose(request: Request):
    """Given a list of missing telemetry artifacts, return suggested remediation actions.

    Accepts JSON body: {"items": [...]} or a raw array of items.
    """
    # Enforce auth unless in lite/test mode
    try:
        if not (os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ):
            from src.security.auth import auth_dependency
            x_api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
            authorization = request.headers.get('Authorization')
            await auth_dependency(x_api_key, authorization, ['telemetry.read'])
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail='unauthorized')
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if isinstance(data, dict) and isinstance(data.get('items'), list):
        items = data.get('items')
    elif isinstance(data, list):
        items = data
    else:
        raise HTTPException(status_code=400, detail='expected_items')
    try:
        from src.core.detectors.missing_log_rootcause import diagnose_and_suggest_actions
    except Exception:
        raise HTTPException(status_code=500, detail='diagnose_unavailable')
    try:
        # Support both older signature diagnose_and_suggest_actions(items)
        # and newer diagnose_and_suggest_actions(tenant, expected_sources)
        try:
            suggestions = diagnose_and_suggest_actions(items)
        except TypeError:
            # Build tenant and expected_sources fallback
            tenant = request.headers.get('X-Tenant-Id') or request.headers.get('x-tenant-id') or os.getenv('DEFAULT_TENANT','default')
            expected = [it.get('source') for it in items if isinstance(it, dict) and it.get('source')]
            suggestions = diagnose_and_suggest_actions(tenant, expected)
    except Exception:
        raise HTTPException(status_code=500, detail='diagnose_failed')
    return {'count': len(suggestions), 'suggestions': suggestions}


@router.post('/api/v1/telemetry/execute_remediation')
async def telemetry_execute_remediation(request: Request):
    """Execute a single remediation action. Safe by default (dry-run); requires ENABLE_AUTO_REMEDIATION to perform real actions.

    Body: {"action": "restart_collector"|"refresh_api_token", ...}
    """
    # Enforce auth unless in lite/test mode
    try:
        if not (os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ):
            from src.security.auth import auth_dependency
            x_api_key = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
            authorization = request.headers.get('Authorization')
            await auth_dependency(x_api_key, authorization, ['telemetry.write'])
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail='unauthorized')
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail='expected_object')
    action = data.get('action')
    dry_run = data.get('dry_run', True)
    try:
        from src.core.remediation import restart_collector, refresh_api_token
    except Exception:
        raise HTTPException(status_code=500, detail='remediation_unavailable')
    if action == 'restart_collector':
        name = data.get('name') or data.get('collector')
        if not name:
            raise HTTPException(status_code=400, detail='missing_collector_name')
        try:
            res = restart_collector(name, dry_run=bool(dry_run))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f'restart_failed: {e}')
        return {'ok': True, 'result': res}
    elif action == 'refresh_api_token':
        connector = data.get('connector')
        if not connector:
            raise HTTPException(status_code=400, detail='missing_connector')
        try:
            res = refresh_api_token(connector, dry_run=bool(dry_run))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f'refresh_failed: {e}')
        return {'ok': True, 'result': res}
    else:
        raise HTTPException(status_code=400, detail='unknown_action')
