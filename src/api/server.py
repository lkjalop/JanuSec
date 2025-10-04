from __future__ import annotations
from fastapi import Depends
from security.auth import require_scopes

import asyncio
import logging
import os
import time
from collections import deque
from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union, Iterator, cast
import hashlib
from fastapi import Depends
from pydantic import BaseModel

from fastapi import HTTPException, Depends
from pydantic import BaseModel, ConfigDict, Field
from starlette.requests import Request
from starlette.responses import HTMLResponse

from .app import app
from .auth import check_admin_token, check_admin_token_async, _validate_oidc_token
from .session import create_session_cookie
from .csrf import CSRF_COOKIE
from database_adapter import db_manager

# --- Test Compatibility Monkeypatch ---
# Some legacy tests expect a 'requests'-style Response.iter_content API while httpx
# only exposes iter_bytes/iter_text. Add a lightweight alias so tests calling
# response.iter_content(...) function as expected without modifying tests.
try:  # pragma: no cover - defensive
    import httpx
    if not hasattr(httpx.Response, 'iter_content'):
        def _iter_content(self: Any, chunk_size: int | None = None) -> Any:
            return self.iter_bytes()  # delegate
        httpx.Response.iter_content = _iter_content
except Exception:
    pass
from core.metrics.registry import expected_metrics
from core.threat_modeling.factor_taxonomy import aggregate_threat_model
import json as _json
import pathlib as _pathlib
import asyncio as _asyncio
from core import risk_score as _risk_score
from .auth import check_admin_token
from .auth import check_admin_token_async
from fastapi import UploadFile, File
from ml.dataset_builder import collect_calibration_rows, to_csv, to_html
from security.auth import require_scopes
try:
    # Optional import used only when CLUSTER_MINHASH_ENABLED is set and package is installed
    from datasketch import MinHash  # type: ignore
except Exception:
    MinHash = None  # type: ignore
from core.factor_attribution_store import FACTOR_ATTRIBUTIONS
from core.factor_stats_manager import FACTOR_STATS
from core.labels_store import LABELS, VALID_LABELS
from core.audit import emit as audit_emit, canonical_user as audit_user
from core.flags import get_flag as _get_flag, set_flag as _set_flag, clear_flag as _clear_flag, flags_snapshot as _flags_snapshot, list_overrides as _list_overrides
from core.threat_modeling.reload_watcher import ensure_watcher

from . import runtime_state as _rt
from .alerts_endpoints import (
    ALERT_RING as _ALERT_RING,
    ALERT_RING_LOCK as _ALERT_RING_LOCK,
    append_alert,
    router as _alerts_router,
)
from .analytics_endpoints import router as _analytics_router
from .artifact_endpoints import router as _artifact_router
from .custody import router as _custody_router
from .decisions_stream import publish_decision as _publish_decision  # SSE publisher
from .dependencies import get_platform_state
from .finops_endpoints import finops_overview as _finops_overview_impl, router as _finops_router
from .investigation_endpoints import router as _investigation_router
from .report_endpoints import router as _report_router
from .runtime_state import (
    _RUNTIME,
    DECISION_CACHE,
    EVENT_QUEUE,
    GUARDRAIL_HISTORY_SIZE,
    GUARDRAIL_MIN_SAMPLE,
    LOGGER,
    RECENT_DECISION_WINDOW,
    ServerRuntime,
    _recent_guardrail_fallback,
    _recent_guardrail_select,
    _sanitize_event,
    asn_stats,
    dns_agg,
    get_file_hash_factors,
)
from core.baseline_service import BASELINES
from core.geo_velocity import GEO_VELOCITY
from core.clustering_service import CLUSTERING
from core.enrichment import ENRICHMENT
try:  # pragma: no cover
    from prometheus_client import Histogram as _H  # type: ignore
    _baseline_endpoint_latency = _H('baseline_endpoint_latency_seconds','Baseline endpoint latency',['endpoint'])  # type: ignore
except Exception:  # pragma: no cover
    class _Stub:
        def labels(self,*a,**k): return self
        def observe(self,*a,**k): return None
    _baseline_endpoint_latency = _Stub()
_BASELINE_METRICS = [m.strip() for m in os.getenv('BASELINE_METRICS','score').split(',') if m.strip()]
_BASELINE_USER_FIELDS = [f.strip() for f in os.getenv('BASELINE_USER_FIELDS','user,username,principal').split(',') if f.strip()]
# Clustering defaults
os.environ.setdefault('CLUSTER_MINHASH_ENABLED','1')
if 'CLUSTER_TTL_SECONDS' not in os.environ:
    os.environ.setdefault('CLUSTER_TTL_SECONDS', str(300 * 4))

# Backward compatibility export for tests importing FILE_HASH_FACTORS directly
try:  # pragma: no cover
    FILE_HASH_FACTORS = get_file_hash_factors()
except Exception:  # pragma: no cover
    FILE_HASH_FACTORS = {}

# Backward compatibility: expose DecisionRecord type for legacy tests that import it
try:
    # Prefer the canonical model defined in schemas. This should succeed in normal
    # operation and ensures tests importing DecisionRecord from api.server get the
    # same Pydantic model as other modules (e.g. api.state, api.routes.events).
    from .schemas import DecisionRecord as _DecisionRecord
    DecisionRecord = _DecisionRecord
    globals()['DecisionRecord'] = DecisionRecord
except Exception:
    # Provide a minimal fallback DecisionRecord model so tests importing it do not fail
    # (best-effort; this branch should only be exercised in extreme test isolation).
    from dataclasses import dataclass, field as _dc_field
    from typing import Optional

    @dataclass
    class _FallbackDecisionRecord:
        event_id: str
        verdict: str
        confidence: float
        factors: list[str] = _dc_field(default_factory=list)
        timestamp: float = _dc_field(default_factory=lambda: time.time())
        tenant_id: Optional[str] = None
        processing_time_ms: Optional[float] = None

        def model_dump(self) -> dict[str, Any]:
            return {
                'event_id': self.event_id,
                'verdict': self.verdict,
                'confidence': self.confidence,
                'factors': self.factors,
                'timestamp': self.timestamp,
                'tenant_id': self.tenant_id,
                'processing_time_ms': self.processing_time_ms,
            }

    globals()['DecisionRecord'] = _FallbackDecisionRecord

# Ensure DecisionRecord is part of the module export surface expected by legacy
# imports (e.g. `from api.server import DecisionRecord`).
__all__: list[str] = []
if 'DecisionRecord' not in __all__:
    __all__.append('DecisionRecord')
if 'DECISION_CACHE' not in __all__:
    __all__.append('DECISION_CACHE')


@app.get('/api/v1/dlq', summary='List DLQ entries')
async def dlq_list(limit: int = 50, request: Request = None) -> dict:
    if request is not None:
        await check_admin_token_async(request)
    try:
        from db.adapter import fetch as db_fetch
        # include next_retry for scheduling visibility
        rows = await db_fetch('SELECT id, event_id, payload, error, attempts, last_attempt, next_retry FROM decisions_dlq ORDER BY COALESCE(next_retry, last_attempt) ASC LIMIT $1', limit)
        return {'count': len(rows or []), 'rows': rows}
    except Exception as exc:
        LOGGER.debug('dlq_list failed: %s', exc, exc_info=True)
        raise HTTPException(status_code=500, detail='dlq_list_failed')


@app.get('/api/v1/dlq/{dlq_id}', summary='Get DLQ entry')
async def dlq_get(dlq_id: int, request: Request = None) -> dict:
    if request is not None:
        await check_admin_token_async(request)
    try:
        from db.adapter import fetch as db_fetch
        rows = await db_fetch('SELECT id, event_id, payload, error, attempts, last_attempt, next_retry FROM decisions_dlq WHERE id=$1', dlq_id)
        if not rows:
            raise HTTPException(status_code=404, detail='dlq_not_found')
        return {'row': rows[0]}
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.debug('dlq_get failed: %s', exc, exc_info=True)
        raise HTTPException(status_code=500, detail='dlq_get_failed')


@app.post('/api/v1/dlq/{dlq_id}/retry', summary='Retry a DLQ entry immediately')
async def dlq_retry(dlq_id: int, request: Request = None) -> dict:
    if request is not None:
        await check_admin_token_async(request)
    try:
        from db.adapter import fetch as db_fetch
        rows = await db_fetch('SELECT id, event_id, payload, error, attempts FROM decisions_dlq WHERE id=$1', dlq_id)
        if not rows:
            raise HTTPException(status_code=404, detail='dlq_not_found')
        row = rows[0]
        # call DLQManager attempt redeliver logic directly
        try:
            from src.core.dlq_manager import DLQManager
            mgr = getattr(__import__('src.api.startup', fromlist=['runtime_state']).runtime_state, 'dlq', None)
            if mgr and hasattr(mgr, '_attempt_redeliver'):
                ok = await mgr._attempt_redeliver(row)
                return {'requeued': ok}
        except Exception:
            pass
        raise HTTPException(status_code=500, detail='dlq_retry_failed')
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.debug('dlq_retry failed: %s', exc, exc_info=True)
        raise HTTPException(status_code=500, detail='dlq_retry_failed')


@app.delete('/api/v1/dlq/{dlq_id}', summary='Delete DLQ entry')
async def dlq_delete(dlq_id: int, request: Request = None) -> dict:
    if request is not None:
        await check_admin_token_async(request)
    try:
        from db.adapter import execute as db_execute
        await db_execute('DELETE FROM decisions_dlq WHERE id=$1', dlq_id)
        return {'deleted': True}
    except Exception as exc:
        LOGGER.debug('dlq_delete failed: %s', exc, exc_info=True)
        raise HTTPException(status_code=500, detail='dlq_delete_failed')


@app.post('/api/v1/dlq/{dlq_id}/requeue', summary='Requeue DLQ entry with edited payload')
async def dlq_requeue_as(dlq_id: int, request: Request) -> dict:
    # enforce admin token for requeue-as
    await check_admin_token_async(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    # basic server-side validation/transform
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='payload_must_be_object')
    # require event_id string
    if 'event_id' not in body or not isinstance(body.get('event_id'), str):
        raise HTTPException(status_code=400, detail='event_id_required')
    # factors - coerce into list of strings
    factors = body.get('factors') or []
    if not isinstance(factors, list):
        raise HTTPException(status_code=400, detail='factors_must_be_list')
    body['factors'] = [str(f) for f in factors]
    # verdict
    if 'verdict' not in body or not isinstance(body.get('verdict'), str):
        raise HTTPException(status_code=400, detail='verdict_required')
    # confidence - coerce to float between 0 and 1
    conf = body.get('confidence')
    try:
        conff = float(conf) if conf is not None else 0.0
        conff = max(0.0, min(1.0, conff))
        body['confidence'] = conff
    except Exception:
        raise HTTPException(status_code=400, detail='confidence_invalid')
    # optional next_retry can be provided (ISO or epoch). Normalize to epoch seconds
    next_retry = body.get('next_retry')
    norm_next_retry = None
    if next_retry is not None:
        try:
            # accept ISO-like string or numeric epoch
            if isinstance(next_retry, (int, float)):
                norm_next_retry = float(next_retry)
            else:
                import datetime
                dt = datetime.datetime.fromisoformat(str(next_retry))
                norm_next_retry = dt.timestamp()
        except Exception:
            raise HTTPException(status_code=400, detail='next_retry_invalid')
    try:
        from db.adapter import fetch as db_fetch
        rows = await db_fetch('SELECT id, event_id, payload, error, attempts, next_retry FROM decisions_dlq WHERE id=$1', dlq_id)
        if not rows:
            raise HTTPException(status_code=404, detail='dlq_not_found')
        row = rows[0]
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.debug('dlq_requeue lookup failed: %s', exc, exc_info=True)
        raise HTTPException(status_code=500, detail='dlq_lookup_failed')
    # record audit (best-effort)
    try:
        user = audit_user(request=request)
        try:
            audit_emit('dlq_requeue', user, {'dlq_id': dlq_id, 'original': row.get('payload') or {}, 'new_payload': body})
        except Exception:
            pass
    except Exception:
        LOGGER.debug('dlq audit failed', exc_info=True)
    # attempt delivery via DLQ manager path
    try:
        from src.core.dlq_manager import DLQManager
        mgr = getattr(__import__('src.api.startup', fromlist=['runtime_state']).runtime_state, 'dlq', None)
        if mgr and hasattr(mgr, '_attempt_redeliver'):
            deliver_row = dict(row)
            deliver_row['payload'] = body
            ok = await mgr._attempt_redeliver(deliver_row)
            if ok:
                # delete dlq row after explicit requeue-as success
                from db.adapter import execute as db_execute
                await db_execute('DELETE FROM decisions_dlq WHERE id=$1', dlq_id)
                return {'requeued': True}
            else:
                # If next_retry provided, update scheduling
                if norm_next_retry is not None:
                    try:
                        from db.adapter import execute as db_execute
                        await db_execute('UPDATE decisions_dlq SET next_retry=TO_TIMESTAMP($1) WHERE id=$2', norm_next_retry, dlq_id)
                    except Exception:
                        LOGGER.debug('Failed to update next_retry', exc_info=True)
                raise HTTPException(status_code=500, detail='delivery_failed')
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.debug('dlq_requeue delivery failed', exc_info=True)
    raise HTTPException(status_code=500, detail='requeue_failed')


@app.get('/api/v1/dlq/{dlq_id}/audit', summary='Fetch DLQ audit entries')
async def dlq_audit(dlq_id: int, limit: int = 50, request: Request = None) -> dict:
    if request is not None:
        await check_admin_token_async(request)
    try:
        from db.adapter import fetch as db_fetch
        rows = await db_fetch('SELECT id, dlq_id, user_info, original_payload, new_payload, created_at FROM dlq_admin_audit WHERE dlq_id=$1 ORDER BY created_at DESC LIMIT $2', dlq_id, int(limit))
        return {'rows': rows}
    except Exception:
        return {'rows': []}


@app.get('/admin/dlq', summary='DLQ admin UI')
async def dlq_admin_page(request: Request) -> Any:
    """Simple internal admin page showing DLQ entries with retry/delete actions.

    This view requires `ADMIN_UI_TOKEN` to be set and presented via
    `Authorization: Bearer <token>` or `X-Admin-Token` header. If the env var is
    not set, the UI is permissive for local development.
    """
    # enforce token for admin index as well (async)
    await check_admin_token_async(request)
    html = '''
    <!doctype html>
    <html>
    <head><title>DLQ Admin</title></head>
    <body>
        <div style="margin-bottom:12px"><a href="/admin/sessions">Sessions</a> | <strong>DLQ</strong></div>
        <h1>Decisions DLQ</h1>
        <div id="content">Loading...</div>
        <script>
            async function load(){
                const r = await fetch('/api/v1/dlq');
                const j = await r.json();
                const rows = j.rows || [];
                let out = '<table border="1"><tr><th>ID</th><th>Event</th><th>Attempts</th><th>Error</th><th>Actions</th></tr>';
                for(const row of rows){
                    out += `<tr><td>${row.id}</td><td><a href="/admin/dlq/${row.id}">${row.event_id}</a></td><td>${row.attempts}</td><td>${row.error}</td><td><button onclick="retry(${row.id})">Retry</button> <button onclick="del(${row.id})">Delete</button></td></tr>`
                }
                out += '</table>';
                document.getElementById('content').innerHTML = out;
            }
            async function retry(id){
                await fetch(`/api/v1/dlq/${id}/retry`, {method:'POST'});
                load();
            }
            async function del(id){
                await fetch(`/api/v1/dlq/${id}`, {method:'DELETE'});
                load();
            }
            load();
        </script>
    </body>
    </html>
    '''
    return html


@app.post('/admin/login', summary='Admin login (OIDC)')
async def admin_login(request: Request) -> dict:
    # Accept JSON body with id_token (from OIDC implicit/PKCE flow)
    try:
        j = await request.json()
        id_token = j.get('id_token')
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')
    if not id_token:
        raise HTTPException(status_code=400, detail='id_token_required')
    # validate id_token using OIDC helper
    claims = await _validate_oidc_token(id_token)
    if not claims:
        raise HTTPException(status_code=401, detail='invalid_token')
    user = {'sub': claims.get('sub'), 'email': claims.get('email')}
    cookie_val = create_session_cookie(user)
    # set cookie and csrf token (double-submit) via response
    from starlette.responses import JSONResponse
    resp = JSONResponse({'status': 'ok'})
    resp.set_cookie('janusec_admin_session', cookie_val, httponly=True, samesite='Lax')
    # set csrf cookie as well
    csrf = request.cookies.get(CSRF_COOKIE) or None
    if not csrf:
        from api.csrf import generate_csrf_token
        csrf = generate_csrf_token()
    resp.set_cookie(CSRF_COOKIE, csrf, httponly=False, samesite='Lax')
    return resp


@app.post('/admin/logout', summary='Admin logout')
async def admin_logout(request: Request) -> dict:
    from starlette.responses import JSONResponse
    resp = JSONResponse({'status': 'ok'})
    resp.delete_cookie('janusec_admin_session')
    resp.delete_cookie(CSRF_COOKIE)
    return resp


@app.get('/api/v1/admin/sessions', summary='List admin sessions')
async def admin_sessions_list(request: Request, page: int = 1, per_page: int = 50, user: str | None = None, revoked: str | None = None) -> dict:
    # async auth helper avoids run_until_complete warnings in event loops
    await check_admin_token_async(request)
    page = max(1, int(page or 1))
    per_page = max(1, min(500, int(per_page or 50)))
    offset = (page - 1) * per_page
    clauses = []
    params: list[Any] = []
    idx = 1
    if user:
        clauses.append(f"(user_info->> 'email' ILIKE ${idx} OR user_info->> 'sub' ILIKE ${idx})")
        params.append(f"%{user}%")
        idx += 1
    if revoked is not None:
        # accept '1','0','true','false'
        rflag = str(revoked).lower() in {'1','true','yes'}
        clauses.append(f"revoked = ${idx}")
        params.append(rflag)
        idx += 1
    try:
        from db.adapter import pool as _pool
        async with _pool.acquire() as conn:
            # count
            count_q = 'SELECT COUNT(1) FROM admin_sessions'
            if clauses:
                count_q += ' WHERE ' + ' AND '.join(clauses)
            total = await conn.fetchval(count_q, *params) if params else await conn.fetchval(count_q)
            # data
            q = 'SELECT session_id, user_info, created_at, expires_at, revoked FROM admin_sessions'
            if clauses:
                q += ' WHERE ' + ' AND '.join(clauses)
            q += f' ORDER BY created_at DESC LIMIT {per_page} OFFSET {offset}'
            rows = await conn.fetch(q, *params) if params else await conn.fetch(q)
            return {'total': int(total or 0), 'page': page, 'per_page': per_page, 'rows': [dict(r) for r in rows]}
    except Exception:
        return {'total': 0, 'page': page, 'per_page': per_page, 'rows': []}


@app.get('/api/v1/admin/sessions/export', summary='Export all admin sessions as CSV')
async def admin_sessions_export(request: Request) -> Any:
    await check_admin_token_async(request)
    try:
        from db.adapter import pool as _pool
        async with _pool.acquire() as conn:
            rows = await conn.fetch('SELECT session_id, user_info, created_at, expires_at, revoked FROM admin_sessions ORDER BY created_at DESC')
            # stream as CSV
            lines = ['session_id,user,email,created_at,expires_at,revoked']
            for r in rows:
                ui = r.get('user_info') or {}
                email = ui.get('email') if isinstance(ui, dict) else None
                lines.append(f"{r.get('session_id')},{email or ''},{r.get('created_at')},{r.get('expires_at')},{bool(r.get('revoked'))}")
            from starlette.responses import PlainTextResponse
            return PlainTextResponse('\n'.join(lines), media_type='text/csv')
    except Exception:
        raise HTTPException(status_code=500, detail='export_failed')


@app.post('/api/v1/admin/sessions/{session_id}/revoke', summary='Revoke admin session')
async def admin_sessions_revoke(session_id: str, request: Request) -> dict:
    # use async auth helper
    await check_admin_token_async(request)
    # CSRF enforced by middleware for admin paths
    try:
        from db.adapter import pool as _pool
        async with _pool.acquire() as conn:
            # perform revoke
            await conn.execute('UPDATE admin_sessions SET revoked=TRUE WHERE session_id=$1', session_id)
            # write audit record (best-effort)
            try:
                user = getattr(request.state, 'user', None)
                await conn.execute('INSERT INTO admin_session_audit(session_id, action, user_info, created_at) VALUES($1,$2,$3, NOW())', session_id, 'revoke', dict(user or {}))
            except Exception:
                # swallow audit failures
                pass
            return {'revoked': True}
    except Exception:
        raise HTTPException(status_code=500, detail='revoke_failed')


@app.get('/api/v1/admin/sessions/{session_id}/audit', summary='Fetch session audit entries')
async def admin_session_audit(session_id: str, request: Request, limit: int = 50) -> dict:
    await check_admin_token_async(request)
    try:
        from db.adapter import pool as _pool
        async with _pool.acquire() as conn:
            rows = await conn.fetch('SELECT id, session_id, action, user_info, created_at FROM admin_session_audit WHERE session_id=$1 ORDER BY created_at DESC LIMIT $2', session_id, int(limit))
            return {'rows': [dict(r) for r in rows]}
    except Exception:
        return {'rows': []}


@app.get('/admin/sessions', summary='Admin sessions UI')
async def admin_sessions_page(request: Request) -> Any:
        await check_admin_token_async(request)
        html = '''
        <!doctype html>
        <html>
        <head>
            <title>Admin Sessions</title>
            <style>
                body{font-family:system-ui,Segoe UI,Segoe,Roboto,Arial;color:#111;background:#f7f8fb;padding:20px}
                .nav{margin-bottom:16px}
                table{border-collapse:collapse;width:100%;background:#fff}
                th,td{border:1px solid #ddd;padding:8px;text-align:left}
                th{background:#f0f2f7}
                button{background:#c0392b;color:#fff;border:none;padding:6px 10px;border-radius:4px;cursor:pointer}
                .muted{color:#666}
            </style>
        </head>
        <body>
            <div class="nav"><a href="/admin/dlq">DLQ</a> | <strong>Sessions</strong></div>
                    <h1>Active Admin Sessions</h1>
                    <div style="margin-bottom:12px">
                        <label>Filter user/email: <input id="filter_user" /></label>
                        <label style="margin-left:12px"><input type="checkbox" id="filter_revoked"> Show only revoked</label>
                        <button onclick="applyFilters()" style="margin-left:8px">Apply</button>
                    </div>
                    <div id="content">Loading...</div>
                    <div id="pager" style="margin-top:8px"></div>
                    <div id="confirm" style="display:none;position:fixed;left:0;top:0;right:0;bottom:0;background:rgba(0,0,0,0.4);align-items:center;justify-content:center">
                        <div style="background:#fff;padding:20px;border-radius:6px;margin:auto;max-width:420px">
                            <div id="confirm_text">Confirm action</div>
                            <div style="margin-top:12px;text-align:right"><button id="confirm_cancel">Cancel</button> <button id="confirm_ok" style="background:#c0392b;color:#fff">Confirm</button></div>
                        </div>
                    </div>
                    <script>
                        let currentPage = 1; let sortKey = null; let sortDir = 1;
                        function setSort(key){ if(sortKey===key) sortDir = -sortDir; else { sortKey=key; sortDir=1 } ; load(currentPage); }
                        function exportCSV(){
                          const rows = Array.from(document.querySelectorAll('#content table tr')).slice(1).map(tr=>Array.from(tr.children).slice(0,5).map(td=>`"${td.innerText.replace(/"/g,'""')}"`).join(','));
                          const header = 'session_id,user,created,expires,revoked';
                          const csv = [header].concat(rows).join('\n');
                          // request server CSV for full export
                          const a = document.createElement('a'); a.href = '/api/v1/admin/sessions/export'; a.download = 'admin_sessions.csv'; document.body.appendChild(a); a.click(); a.remove();
                        }
                        function getFilters(){
                            const user = document.getElementById('filter_user').value || null;
                            const revoked = document.getElementById('filter_revoked').checked ? 'true' : null;
                            return {user, revoked};
                        }
                        function applyFilters(){ currentPage = 1; load(); }
                        async function load(page){
                            page = page || currentPage || 1
                            currentPage = page
                            const f = getFilters();
                            let url = `/api/v1/admin/sessions?page=${page}&per_page=10`;
                            if(f.user) url += `&user=${encodeURIComponent(f.user)}`;
                            if(f.revoked) url += `&revoked=${f.revoked}`;
                            const r = await fetch(url);
                            const j = await r.json();
                                                        const rows = j.rows || [];
                                                        if(sortKey){
                                                            rows.sort((a,b)=>{
                                                                let av = a[sortKey]; let bv = b[sortKey];
                                                                if(typeof av === 'object' && av !== null) av = av.email || av.sub || JSON.stringify(av);
                                                                if(typeof bv === 'object' && bv !== null) bv = bv.email || bv.sub || JSON.stringify(bv);
                                                                av = av == null ? '' : String(av);
                                                                bv = bv == null ? '' : String(bv);
                                                                if(av < bv) return -1*sortDir; if(av > bv) return 1*sortDir; return 0;
                                                            })
                                                        }
                            let out = '<table><tr><th onclick="setSort(\'session_id\')">Session ID</th><th onclick="setSort(\'user_info\')">User</th><th onclick="setSort(\'created_at\')">Created</th><th onclick="setSort(\'expires_at\')">Expires</th><th onclick="setSort(\'revoked\')">Revoked</th><th>Actions</th></tr>';
                            for(const row of rows){
                                let user = row.user_info || {};
                                let email = user.email || user.sub || 'unknown';
                                out += `<tr><td>${row.session_id}</td><td>${email}</td><td>${row.created_at}</td><td>${row.expires_at}</td><td>${row.revoked}</td><td><button onclick="confirmRevoke('${row.session_id}','${email}')">Revoke</button></td></tr>`
                            }
                            out += '</table>';
                              out += '<div style="margin-top:8px"><button onclick="exportCSV()">Export CSV</button></div>';
                            document.getElementById('content').innerHTML = out;
                            const total = j.total || 0;
                            const per = j.per_page || 10;
                            const pages = Math.max(1, Math.ceil(total / per));
                            document.getElementById('pager').innerHTML = `<button ${page<=1?'disabled':''} onclick="load(${page-1})">Prev</button> Page ${page} of ${pages} <button ${page>=pages?'disabled':''} onclick="load(${page+1})">Next</button>`;
                        }
                        function confirmRevoke(id, who){
                            const cs = document.getElementById('confirm');
                            document.getElementById('confirm_text').innerText = `Revoke session ${id} for ${who}?`;
                            cs.style.display = 'flex';
                            document.getElementById('confirm_cancel').onclick = ()=>{ cs.style.display='none'; }
                            document.getElementById('confirm_ok').onclick = async ()=>{ cs.style.display='none'; await revoke(id); }
                        }
                        async function revoke(id){
                            const csrf = document.cookie.split('; ').find(row=>row.startsWith('janusec_csrf='))?.split('=')[1];
                            await fetch(`/api/v1/admin/sessions/${id}/revoke`, {method:'POST', headers:{'x-csrf-token':csrf}});
                            load(currentPage);
                        }
                        load(1);
                    </script>
        </body>
        </html>
        '''
        return html


@app.get('/admin/dlq/{dlq_id}', summary='DLQ row detail UI')
async def dlq_detail_page(dlq_id: int, request: Request) -> Any:
    # enforce admin token for detail view (async)
    await check_admin_token_async(request)
    # Build HTML without Python f-string to avoid colliding with JS template literals
    html = '''
    <!doctype html>
    <html>
    <head><title>DLQ Detail</title></head>
    <body>
        <h1>DLQ Row</h1>
        <div id="content">Loading...</div>
        <script>
            const DLQ_ID = ''' + str(dlq_id) + ''';
            async function load(){
                const r = await fetch('/api/v1/dlq/' + DLQ_ID);
                const j = await r.json();
                const row = j.row;
                // show operator identity if present
                let out = '';
                out += `<p><strong>Event:</strong> ${row.event_id}</p>`;
                out += `<pre id="payload">${JSON.stringify(row.payload,null,2)}</pre>`;
                out += `<p>Error: ${row.error}</p>`;
                out += `<h3>Edit payload and requeue-as</h3>`;
                out += `<textarea id="edit" style="width:90%;height:200px">${JSON.stringify(row.payload,null,2)}</textarea><br/>`;
                const nr = row.next_retry ? new Date(row.next_retry).toISOString().slice(0,19) : '';
                out += `Next retry (optional): <input type="datetime-local" id="next_retry" value="${nr}"><br/>`;
                out += `<button onclick="confirmRequeue()">Requeue-as</button> <button onclick="del()">Delete</button>`;
                out += `<h4>Audit</h4><div id="audit">Loading audit...</div>`;
                document.getElementById('content').innerHTML = out;
                // fetch audit entries
                fetch('/api/v1/dlq/' + DLQ_ID + '/audit').then(r=>r.json()).then(j=>{
                    const audits = j.rows || [];
                    let ao = '<ul>';
                    for(const a of audits){
                        ao += `<li>${new Date(a.created_at).toLocaleString()} by ${a.user_info?.email || a.user_info?.sub || 'unknown'}: <pre>${JSON.stringify(a.new_payload,null,2)}</pre></li>`;
                    }
                    ao += '</ul>';
                    document.getElementById('audit').innerHTML = ao;
                }).catch(e=>{ document.getElementById('audit').innerHTML = 'Failed to load audit'; });
            }
            function confirmRequeue(){
                const ok = confirm('Confirm requeue-as (this will attempt delivery and create an audit record). Are you sure?');
                if(!ok) return;
                requeue();
            }
            async function requeue(){
                let edited = document.getElementById('edit').value;
                try{ JSON.parse(edited); }catch(e){ alert('Invalid JSON payload'); return; }
                const nr = document.getElementById('next_retry').value;
                const payload = JSON.parse(edited);
                if(nr){ payload.next_retry = new Date(nr).toISOString(); }
                // include CSRF token from cookie as header (double-submit)
                const csrf = document.cookie.split('; ').find(row=>row.startsWith('janusec_csrf='))?.split('=')[1];
                const r = await fetch('/api/v1/dlq/' + DLQ_ID + '/requeue', {method:'POST', headers:{'Content-Type':'application/json', 'x-csrf-token': csrf}, body: JSON.stringify(payload)});
                if(r.ok){ alert('Requeued'); window.location.href='/admin/dlq'; } else { alert('Requeue failed'); }
            }
            async function del(){
                await fetch('/api/v1/dlq/' + DLQ_ID, {method:'DELETE'});
                window.location.href='/admin/dlq';
            }
            load();
        </script>
    </body>
    </html>
    '''
    return html

# For tests: capture persisted decisions here when persistence is attempted
_PERSISTED_DECISIONS: list[dict] = []

# Provide a lightweight decisions_repo adapter by default so server can call .persist()
try:
    if 'decisions_repo' not in globals() or globals().get('decisions_repo') is None:
        from repositories.decisions_repo_adapter import repo as decisions_repo
        globals()['decisions_repo'] = decisions_repo
except Exception:
    # best-effort: leave decisions_repo unset if adapter not available
    pass


# --- Startup: auto-load and optionally watch baseline sigmoid model ---
async def _auto_load_sigmoid_model():  # pragma: no cover (startup side-effect)
    try:
        enabled = os.getenv('RISK_SIGMOID_AUTO_LOAD', '1').lower() in {'1','true','yes'}
        # prefer a 'current' alias if present
        model_path = os.getenv('RISK_SIGMOID_MODEL_PATH', '') or ''
        if not model_path:
            # check models/current (symlink) and models/current.json fallback
            cur = _pathlib.Path('models') / 'current'
            cur_json = _pathlib.Path('models') / 'current.json'
            if cur.exists():
                model_path = str(cur)
            elif cur_json.exists():
                model_path = str(cur_json)
            else:
                model_path = 'models/baseline_sigmoid.json'
        watch_sec = int(os.getenv('RISK_SIGMOID_WATCH_SECONDS', '0') or 0)
        p = _pathlib.Path(model_path)
        last_mtime = None

        async def _load_once():
            nonlocal last_mtime
            if not p.exists():
                return
            try:
                mt = p.stat().st_mtime
                if last_mtime is not None and mt == last_mtime:
                    return
                data = _json.loads(p.read_text(encoding='utf-8'))
                if str(data.get('type')) == 'sigmoid' and 'k' in data and 'x0' in data:
                    _risk_score.apply_sigmoid_override(float(data['k']), float(data['x0']))
                    last_mtime = mt
            except Exception:
                pass

        if enabled:
            await _load_once()
            if watch_sec > 0:
                async def _watch():
                    while True:
                        try:
                            await _load_once()
                        except Exception:
                            pass
                        await _asyncio.sleep(watch_sec)
                _asyncio.create_task(_watch())
    except Exception:
        pass

# --- Calibration dataset exports ---
@app.get('/api/v1/risk/calibration/export.csv')
async def calibration_export_csv(limit: int = 1000):
    rows = collect_calibration_rows(limit=limit)
    csv_text = to_csv(rows)
    from fastapi import Response
    return Response(content=csv_text, media_type='text/csv')


@app.get('/api/v1/risk/calibration/export.html')
async def calibration_export_html(limit: int = 1000):
    rows = collect_calibration_rows(limit=limit)
    html_text = to_html(rows)
    from fastapi import Response
    return Response(content=html_text, media_type='text/html')


# --- Model registry endpoints ---
@app.get('/api/v1/models/registry')
async def list_models():
    reg = _pathlib.Path('models/registry')
    idx = {}
    try:
        p = reg / 'index.json'
        if p.exists():
            idx = _json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        idx = {}
    return {'registry': idx}


class AliasPayload(BaseModel):
    alias: str
    model_name: str


@app.post('/api/v1/models/alias')
async def set_alias(payload: AliasPayload, request: Request):
    # require admin (async-aware)
    await check_admin_token_async(request)
    reg = _pathlib.Path('models/registry')
    p = reg / 'index.json'
    idx = {}
    try:
        if p.exists():
            idx = _json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        idx = {}
    aliases = idx.get('aliases', {})
    aliases[payload.alias] = payload.model_name
    idx['aliases'] = aliases
    try:
        p.write_text(_json.dumps(idx, indent=2), encoding='utf-8')
    except Exception:
        raise HTTPException(status_code=500, detail='write_failed')
    try:
        user = audit_user(request=request)
        audit_emit('model_alias_set', user, {'alias': payload.alias, 'model': payload.model_name})
    except Exception:
        pass
    return {'ok': True, 'alias': payload.alias, 'model': payload.model_name}


@app.post('/api/v1/models/promote')
async def promote_model_api(name: str | None = None, alias: str | None = None, file: UploadFile = File(...), request: Request = None):
    # require admin
    await check_admin_token_async(request)
    registry = _pathlib.Path('models/registry')
    registry.mkdir(parents=True, exist_ok=True)
    if not file:
        raise HTTPException(status_code=400, detail='no_file')
    content = await file.read()
    tmp = registry / f'upload_tmp_{int(time.time())}.json'
    tmp.write_bytes(content)
    src = str(tmp)
    # call promote CLI logic (reuse module)
    try:
        from ml.cli.promote_model import promote
        res = promote(src, name, alias)
        if res != 0:
            raise Exception('promote_failed')
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    try:
        user = audit_user(request=request)
        audit_emit('model_promote', user, {'name': name, 'alias': alias, 'src': tmp.name})
    except Exception:
        pass
    # return index
    p = registry / 'index.json'
    idx = {}
    try:
        if p.exists():
            idx = _json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        idx = {}
    return {'registry': idx}
DECISIONS_REPO = globals().get('decisions_repo')

# Ensure decisions_repo provides a persist callable; if not, try to import adapter explicitly
try:
    dec_repo = globals().get('decisions_repo')
    if not (dec_repo and callable(getattr(dec_repo, 'persist', None))):
        from repositories.decisions_repo_adapter import repo as decisions_repo
        globals()['decisions_repo'] = decisions_repo
except Exception:
    pass


async def detections_governance_report(limit_trends: int = 50, min_sessions: int = 2, top_n: int = 15) -> Any:
    """Compatibility shim providing governance report structure for legacy imports."""
    from core.hunt.sidecar_session import get_sidecar_manager

    manager = get_sidecar_manager()
    try:
        trends = manager.coverage_trends(limit=limit_trends)
    except Exception:
        trends = []
    try:
        promotion = manager.promotion_candidates(min_sessions=min_sessions, top_n=top_n)
    except Exception:
        promotion = []

    active_sessions = 0
    try:
        active_sessions = len(getattr(manager, '_sessions', {}))
    except Exception:
        active_sessions = 0

    summary = {
        'active_sessions': active_sessions,
        'promotion_candidates': len(promotion),
        'coverage_trend_points': len(trends),
    }

    overrides: dict[str, Any] = {}
    try:
        overrides = getattr(manager, 'severity_weight_overrides', {}) or {}
    except Exception:
        overrides = {}

    meta = {
        'generated_at': time.time(),
        'limit_trends': limit_trends,
        'min_sessions': min_sessions,
        'top_n': top_n,
    }

    return {
        'summary': summary,
        'trends': trends,
        'promotion_candidates': promotion,
        'effective_severity_weight_overrides': overrides,
        'meta': meta,
    }


@app.get('/api/v1/factors/promotion/status')  # type: ignore[misc]
async def factor_promotion_status(request: Request, limit: int = 500) -> dict[str, Any]:
    tenant_id = request.headers.get('X-Tenant-ID') or request.headers.get('x-tenant-id')
    if not tenant_id:
        raise HTTPException(status_code=400, detail='tenant_required')
    decisions = []
    try:
        # 1. Try real module (tests monkeypatch repositories.decisions_repo.list_recent)
        try:  # pragma: no cover - defensive import
            import repositories.decisions_repo as real_mod  # type: ignore
            if hasattr(real_mod, 'list_recent'):
                decisions = await real_mod.list_recent(limit, tenant_id)  # type: ignore
        except Exception:
            pass
        # 2. If still empty, try adapter instance list_recent if dynamically attached
        if not decisions and DECISIONS_REPO and hasattr(DECISIONS_REPO, 'list_recent'):
            try:
                decisions = await DECISIONS_REPO.list_recent(limit, tenant_id)  # type: ignore
            except Exception:
                decisions = []
        # 3. Fallback to adapter list_recent_decisions
        if not decisions and DECISIONS_REPO and hasattr(DECISIONS_REPO, 'list_recent_decisions'):
            try:
                decisions = await DECISIONS_REPO.list_recent_decisions(limit, tenant_id)  # type: ignore
            except Exception:
                decisions = []
    except Exception:
        decisions = []
    counts: dict[str, int] = {}
    for dec in decisions or []:
        facs = dec.get('factors') if isinstance(dec, dict) else getattr(dec, 'factors', None)
        if not facs:
            continue
        for f in facs:
            if isinstance(f, str):
                counts[f] = counts.get(f, 0) + 1
    try:
        from core.quality.factor_quality import get_quality_manager  # type: ignore
        qm = get_quality_manager()
        suppressed: set[str] = getattr(qm, 'suppressed', set())
    except Exception:
        suppressed = set()
    promotion_min_sessions = int(os.getenv('PROMOTION_MIN_SESSIONS', '3') or 3)
    entries = []
    for factor, count in sorted(counts.items(), key=lambda it: (-it[1], it[0])):
        is_suppressed = factor in suppressed
        if is_suppressed:
            status = 'observe'
        elif count >= promotion_min_sessions:
            status = 'candidate'
        else:
            status = 'insufficient_data'
        entries.append({'factor': factor, 'observations': count, 'suppressed': is_suppressed, 'status': status})
    note = 'No recent factor observations' if not entries else 'Sorted by observation count (desc)'
    return {'tenant_id': tenant_id, 'factors': entries, 'note': note}


async def finops_overview(tenant_id: str | None = None, alpha: float = 0.3, k: float = 3.0) -> Any:
    """Compatibility wrapper delegating to finops endpoints while preserving legacy import path."""
    scope = {
        'type': 'http',
        'asgi': {'version': '3.0', 'spec_version': '2.1'},
        'method': 'GET',
        'headers': [],
        'path': '/api/v1/finops/overview',
        'query_string': b'',
        'client': ('internal', 0),
        'server': ('internal', 0),
        'scheme': 'http',
        'app': app,
        'state': {},
    }
    request = Request(scope)
    return await _finops_overview_impl(request, tenant_id=tenant_id, alpha=alpha, k=k)

# Start scenario watcher if enabled (hot-reload)
try:  # pragma: no cover
    ensure_watcher()
except Exception:
    pass

from contextlib import asynccontextmanager


@asynccontextmanager
async def _lifespan(app):
    # Startup
    try:
        CLUSTERING.start()
    except Exception:
        LOGGER.debug('Failed to start clustering eviction loop', exc_info=True)
    # Backward compatible: run startup model loader here (replacing deprecated on_event)
    try:
        await _auto_load_sigmoid_model()
    except Exception:
        LOGGER.debug('Sigmoid model auto-load failed during startup', exc_info=True)
    try:
        yield
    finally:
        # Shutdown
        try:
            CLUSTERING.stop()
        except Exception:
            LOGGER.debug('Failed to stop clustering eviction loop', exc_info=True)


app.router.lifespan_context = _lifespan  # type: ignore[attr-defined]


class LogEvent(BaseModel):  # type: ignore[misc]
    """Normalized event representation for batch ingestion."""

    id: str | None = Field(default=None, min_length=1, max_length=128, description='Event identifier supplied by the caller')
    host: str | None = Field(default=None, max_length=255, description='Hostname or agent identifier associated with the event')
    dns_rcode: int | str | None = Field(default=None, description='DNS response code, numeric or textual')
    process: dict[str, Any] | None = Field(default=None, description='Process-level metadata for the event')
    parent_process: dict[str, Any] | None = Field(default=None, description='Parent process metadata if available')
    details: dict[str, Any] = Field(default_factory=dict, description='Additional structured context for the event')

    model_config = ConfigDict(extra='allow')


class LogBatchRequest(BaseModel):  # type: ignore[misc]
    """Request schema for the /api/v1/endpoints/log_batch endpoint."""

    events: list[LogEvent] = Field(default_factory=list, min_length=1, description='Events to ingest and evaluate')
    classify: bool = Field(default=False, description='Run scoring/classification pipeline for the events')
    send_alerts: bool = Field(default=False, description='Emit alerts for qualifying events')
    include_rules: bool = Field(default=False, description='Evaluate detection rules against the events')
    tenant_id: str | None = Field(default=None, max_length=64, description='Tenant context for the ingestion batch')


class IncidentCreate(BaseModel):  # type: ignore[misc]
    artifact_id: str = Field(..., description='Associated artifact or event id')
    title: str = Field(..., max_length=200)
    severity: str = Field(default='high')
    description: str | None = None
    tenant_id: str | None = None

class VerdictOverride(BaseModel):  # type: ignore[misc]
    verdict: str = Field(..., description='New verdict, e.g. BENIGN|SUSPICIOUS|MALICIOUS|OBSERVE')
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    reason: str | None = Field(None, max_length=500)
    tenant_id: str | None = None

_INCIDENT_STORE: list[dict[str, Any]] = []

@app.post('/api/v1/incidents', summary='Create a security incident')  # type: ignore[misc]
async def create_incident(payload: IncidentCreate, auth=Depends(require_scopes('factors.search'))) -> dict[str, Any]:
    item = payload.model_dump()
    item['id'] = f"inc-{int(time.time() * 1000)}"
    item['ts'] = time.time()
    _INCIDENT_STORE.append(item)
    return {'incident': item}

@app.get('/api/v1/incidents', summary='List recent incidents')  # type: ignore[misc]
async def list_incidents(limit: int = 50, tenant_id: str | None = None, auth=Depends(require_scopes('factors.search'))) -> dict[str, Any]:
    rows = [i for i in reversed(_INCIDENT_STORE) if (not tenant_id or i.get('tenant_id') == tenant_id)]
    return {'incidents': rows[:limit], 'count': min(len(rows), limit)}

@app.patch('/api/v1/decisions/{event_id}/override', summary='Override decision verdict/confidence')  # type: ignore[misc]
async def decision_override(event_id: str, payload: VerdictOverride, auth=Depends(require_scopes('factors.search'))) -> dict[str, Any]:
    dec = DECISION_CACHE.get(event_id)
    if not dec:
        raise HTTPException(status_code=404, detail='decision_not_found')
    # Update underlying decision structure (dict or object)
    try:
        if isinstance(dec, dict):
            dec['verdict'] = payload.verdict
            if payload.confidence is not None:
                dec['confidence'] = payload.confidence
            dec['override_reason'] = payload.reason
            dec['overridden_ts'] = time.time()
        else:
            dec.verdict = payload.verdict
            if payload.confidence is not None:
                dec.confidence = payload.confidence
            dec.override_reason = payload.reason
            dec.overridden_ts = time.time()
    except Exception:
        raise HTTPException(status_code=500, detail='override_failed')
    # Re-publish updated decision to SSE
    # Coerce values to expected types for _record_decision
    verdict_val = (dec.get('verdict') if isinstance(dec, dict) else getattr(dec, 'verdict', 'OBSERVE')) or 'OBSERVE'
    confidence_val = (dec.get('confidence') if isinstance(dec, dict) else getattr(dec, 'confidence', 0.0)) or 0.0
    _record_decision(event_id, str(verdict_val), float(confidence_val), [])
    return {'status': 'overridden', 'event_id': event_id, 'verdict': (dec.get('verdict') if isinstance(dec, dict) else getattr(dec,'verdict', None)), 'confidence': (dec.get('confidence') if isinstance(dec, dict) else getattr(dec,'confidence', None))}



@dataclass
class LogBatchContext:
    """Runtime options shared while processing a log batch."""

    runtime: ServerRuntime
    include_rules: bool
    classify: bool
    send_alerts: bool
    tenant_id: str | None
    nx_enabled: bool
    dedup_ttl: float


async def _guardrail_single_pass(
    orchestrator: Any,
    alerts_repo: Any,
    queue_util_threshold: float = 0.85,
    drift_threshold: float = 0.4,
    latency_thresh: float = 2500.0,
    fallback_ratio_threshold: float = 0.25,
    recent_fallback: list[int] | None = None,
    recent_select: list[int] | None = None,
) -> None:
    """Evaluate guardrail conditions and emit alerts for degraded states."""
    if alerts_repo is None:
        return

    fallback_buffer = recent_fallback if recent_fallback is not None else _recent_guardrail_fallback
    select_buffer = recent_select if recent_select is not None else _recent_guardrail_select
    alerts: list[tuple[str, dict[str, Any]]] = []

    try:
        stats = EVENT_QUEUE.stats() if EVENT_QUEUE else {}
    except Exception as exc:
        LOGGER.debug('Unable to collect event queue stats: %s', exc, exc_info=exc)
        stats = {}
    depth = stats.get('depth')
    max_size = stats.get('max_size') or 0
    if depth is not None and max_size:
        util = depth / max_size if max_size else 0.0
        if util >= queue_util_threshold:
            alerts.append(('queue', {'utilization': round(util, 3), 'depth': depth, 'max_size': max_size}))

    drift_value: float | None
    try:
        gauges = getattr(getattr(orchestrator, 'metrics', None), 'gauges', {})
        drift_value = gauges.get('factor_freq_js_divergence')
    except Exception as exc:
        LOGGER.debug('Guardrail metric lookup failed: %s', exc, exc_info=exc)
        drift_value = None
    if drift_value is not None and drift_value >= drift_threshold:
        alerts.append(('drift', {'drift': drift_value}))

    window = list(DECISION_CACHE.values())[-RECENT_DECISION_WINDOW:]
    latencies = [float(getattr(rec, 'processing_time_ms', 0) or 0) for rec in window if getattr(rec, 'processing_time_ms', None) is not None]
    if latencies:
        latencies.sort()
        idx = max(int(len(latencies) * 0.95) - 1, 0)
        p95 = latencies[idx]
        avg = sum(latencies) / len(latencies)
        if p95 >= latency_thresh:
            alerts.append(('latency', {'p95': p95, 'avg': avg, 'samples': len(latencies)}))

    fallback_count = 0
    for rec in window:
        factors = getattr(rec, 'factors', []) or []
        if any('hash_provider' in str(f) for f in factors):
            fallback_count += 1
    total = len(window)

    buffer = deque(select_buffer, maxlen=GUARDRAIL_HISTORY_SIZE)
    buffer.append(total)
    select_buffer.clear()
    select_buffer.extend(buffer)

    buffer = deque(fallback_buffer, maxlen=GUARDRAIL_HISTORY_SIZE)
    buffer.append(fallback_count)
    fallback_buffer.clear()
    fallback_buffer.extend(buffer)

    if total >= GUARDRAIL_MIN_SAMPLE:
        ratio = fallback_count / total if total else 0.0
        if ratio >= fallback_ratio_threshold:
            alerts.append(('embedding', {'fallback_ratio': round(ratio, 3), 'window': total}))

    for category, details in alerts:
        try:
            message = f'{category}_guardrail_triggered'
            await alerts_repo.insert_alert('system', category, 'warning', message, details, f'guardrail-{category}')
        except Exception as exc:
            LOGGER.warning('Failed to emit guardrail alert for %s: %s', category, exc, exc_info=exc)

def _configure_nx_tracking(runtime: ServerRuntime) -> tuple[bool, float]:
    """Prepare NX tracking state for the current batch."""
    threshold_raw = os.getenv('ZEEK_NXDOMAIN_RATE_THRESHOLD', '0.35')
    try:
        current_threshold = float(threshold_raw)
    except ValueError:
        current_threshold = runtime.nx_threshold_cache
    nx_enabled = os.getenv('NX_RATE_TRACKER_ENABLED', '1').lower() not in {'0', 'false', 'no'}
    runtime.nx_tracker_enabled = nx_enabled
    if not nx_enabled:
        runtime.reset_nx_tracker(current_threshold)
    elif abs(current_threshold - runtime.nx_threshold_cache) > 1e-9:
        runtime.reset_nx_tracker(current_threshold)
    return nx_enabled, current_threshold


async def _process_endpoint_event(event_model: LogEvent, ctx: LogBatchContext) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Normalize, classify, and optionally escalate a single endpoint event."""
    event = event_model.model_dump()
    event_id = event.get('id') or f"evt-{int(time.time()*1000)}"
    event['id'] = event_id

    if ctx.nx_enabled:
        host = event.get('host')
        if host:
            tracker = ctx.runtime.nx_rate_tracker[host]
            rcode = event.get('dns_rcode')
            if rcode is not None:
                is_nx = False
                if isinstance(rcode, str) and 'NXDOMAIN' in rcode.upper():
                    is_nx = True
                elif isinstance(rcode, int) and rcode == 3:
                    is_nx = True
                tracker.append(is_nx)
            event['zeek_dns_nxdomain'] = sum(tracker)
            event['zeek_dns_total'] = len(tracker)

    dns_agg.record(event.get('host'), event.get('dns_rcode'))
    asn_stats.record(event.get('asn'))

    # Dynamic lookup of rules engine so late wiring (startup init) is respected
    _re = getattr(_rt, 'rules_engine', None)
    hits = _re.evaluate_event(event) if (ctx.include_rules and _re and hasattr(_re, 'evaluate_event')) else []
    rules = [hit.rule for hit in hits]
    if ctx.classify and _re and hasattr(_re, 'score_and_classify'):
        classification = _re.score_and_classify(hits)
    else:
        classification = {'verdict': 'OBSERVE', 'score': 0.0}

    sanitized = _sanitize_event(event, rules, classification)
    async with ctx.runtime.get_sanitized_lock():
        ctx.runtime.sanitized_events.appendleft(sanitized)

    processed_event = {
        'id': event_id,
        'rules': rules,
        'verdict': sanitized['verdict'],
        'score': sanitized['score'],
    }

    # ---------------- Alert Clustering Integration ----------------
    try:
        # Build a lightweight signature: sorted rule ids + sorted factor subset + normalized IOC tokens
        def _normalize_token(t: str) -> str:
            return (t or '').strip().lower()

        # Use up to N factors to avoid huge signatures
        factor_subset = sorted([f for f in rules if isinstance(f, str)])
        # Also include a selection of factors from sanitized event
        extra_factors = sorted([_normalize_token(str(f)) for f in (sanitized.get('factors') or [])]) if sanitized.get('factors') else []
        sig_parts: list[str] = []
        if factor_subset:
            sig_parts.append('|'.join(factor_subset))
        if extra_factors:
            sig_parts.append('|'.join(extra_factors[:8]))
        # Include normalized IOC tokens from details if present (ip, domain, url, hash)
        details = event.get('details') or {}
        iocs: list[str] = []
        for k in ('ip','ip_address','domain','url','hash'):
            v = details.get(k) or event.get(k)
            if v:
                if isinstance(v, (list,tuple)):
                    iocs.extend([_normalize_token(str(x)) for x in v])
                else:
                    iocs.append(_normalize_token(str(v)))
        if iocs:
            sig_parts.append('|'.join(sorted(iocs)[:64]))

        raw_sig = '::'.join(sig_parts) or event.get('host') or 'generic'
        # Optionally use MinHash for large token sets to approximate Jaccard
        minhash_enabled = os.getenv('CLUSTER_MINHASH_ENABLED','0').lower() in {'1','true','yes'}
        cluster_ttl = os.getenv('CLUSTER_TTL_SECONDS')
        try:
            ttl_val = int(cluster_ttl) if cluster_ttl is not None else None
            # If an explicit TTL is provided, update CLUSTERING instance
            if ttl_val is not None:
                CLUSTERING.ttl_seconds = ttl_val
        except Exception:
            pass

        if minhash_enabled and (len(iocs) + len(extra_factors)) > 32:
            # Best-effort: use datasketch MinHash if available
            try:
                from datasketch import MinHash
                mh = MinHash()
                for token in (iocs + extra_factors):
                    mh.update(token.encode('utf-8'))
                cluster_id = mh.hexdigest()
                raw_sig = f"minhash:{cluster_id}"
            except Exception:
                cluster_id = hashlib.sha1(raw_sig.encode('utf-8')).hexdigest()
        else:
            cluster_id = hashlib.sha1(raw_sig.encode('utf-8')).hexdigest()
        cl_res = await CLUSTERING.update(cluster_id, event_id, ts=time.time(), raw_signature=raw_sig, contributors={'rules': factor_subset, 'ioc_count': len(iocs)})
        # Always attach cluster metadata for explainability
        processed_event.setdefault('clusters', []).append({'cluster_id': cluster_id, 'size': cl_res.get('size'), 'novelty': cl_res.get('novelty_score')})
        if cl_res.get('is_duplicate') and cl_res.get('size', 0) > 1:
            dup_factor = f'cluster_duplicate:{cluster_id[:8]}'
            if dup_factor not in rules:
                rules.append(dup_factor)
    except Exception as exc:
        # clustering is best-effort; log exception for visibility in tests
        try:
            LOGGER.debug('Clustering integration failed: %s', exc, exc_info=exc)
        except Exception:
            pass

    # ---------------- Baseline Anomaly Integration ----------------
    try:
        host = event.get('host') or 'unknown'
        # Build metric values dynamically
        metric_values: dict[str, float] = {}
        for m in _BASELINE_METRICS:
            if m == 'score':
                metric_values[m] = float(sanitized.get('score') or 0.0)
            elif m == 'zeek_dns_nxdomain_rate':
                nxd = event.get('zeek_dns_nxdomain') or 0
                total = event.get('zeek_dns_total') or 0
                rate = (float(nxd)/float(total)) if total else 0.0
                metric_values[m] = rate
            elif m in event and isinstance(event[m], (int,float)):
                metric_values[m] = float(event[m])
        for metric, value in metric_values.items():
            res = await BASELINES.get_z('host', host, metric, value)
            if res.get('anomaly'):
                anomaly_factor = f"baseline:anomaly:host:{metric}"
                if anomaly_factor not in rules:
                    rules.append(anomaly_factor)
                processed_event.setdefault('anomalies', []).append({
                    'entity_type': 'host',
                    'entity_id': host,
                    'metric': metric,
                    'z': res['z'],
                    'mean': res['mean'],
                    'stddev': res['stddev'],
                    'samples': res['samples']
                })
        # User entity baselines
        user_id = None
        for f in _BASELINE_USER_FIELDS:
            if f in event and event[f]:
                user_id = str(event[f])
                break
        if user_id:
            for metric, value in metric_values.items():
                res_u = await BASELINES.get_z('user', user_id, metric, value)
                if res_u.get('anomaly'):
                    anomaly_factor = f"baseline:anomaly:user:{metric}"
                    if anomaly_factor not in rules:
                        rules.append(anomaly_factor)
                    processed_event.setdefault('anomalies', []).append({
                        'entity_type': 'user',
                        'entity_id': user_id,
                        'metric': metric,
                        'z': res_u['z'],
                        'mean': res_u['mean'],
                        'stddev': res_u['stddev'],
                        'samples': res_u['samples']
                    })
        # Geo velocity check (user-based if location present)
        lat = event.get('latitude') or event.get('lat')
        lon = event.get('longitude') or event.get('lon')
        if user_id and isinstance(lat,(int,float)) and isinstance(lon,(int,float)):
            gv = await GEO_VELOCITY.update('user', user_id, float(lat), float(lon))
            if gv.get('anomaly'):
                factor = 'geo:velocity_improbable'
                if factor not in rules:
                    rules.append(factor)
                processed_event.setdefault('anomalies', []).append({
                    'entity_type': 'user',
                    'entity_id': user_id,
                    'metric': 'geo_velocity',
                    'speed_kmh': gv.get('speed_kmh'),
                    'distance_km': gv.get('distance_km'),
                    'delta_seconds': gv.get('delta_seconds')
                })
    except Exception:
        pass

    # ---------------- Enrichment completeness ----------------
    try:
        tenant_ctx = ctx.tenant_id or os.getenv('DEFAULT_TENANT','default')
        enrich_res = ENRICHMENT.completeness(event, tenant_ctx)
        processed_event['enrichment'] = enrich_res
        if enrich_res.get('completeness', 1.0) < 1.0:
            ef = 'enrich:incomplete'
            if ef not in rules:
                rules.append(ef)
    except Exception:
        pass

    # Build a best-effort meta payload with any baseline/geo signals computed above
    meta_payload: dict[str, Any] = {}
    try:
        # If baseline anomalies were appended to processed_event, include them
        if 'anomalies' in processed_event:
            meta_payload['anomalies'] = processed_event.get('anomalies')
    except Exception:
        pass
    _record_decision(event_id, sanitized['verdict'] or 'OBSERVE', sanitized['score'] or 0.0, rules, meta_payload)

    # Attach tenant context to decision object (enables tenant-aware reporting)
    try:
        dec_obj = DECISION_CACHE.get(event_id)
        if dec_obj is not None and not getattr(dec_obj, 'tenant_id', None):
            dec_obj.tenant_id = ctx.tenant_id or os.getenv('DEFAULT_TENANT','default')
    except Exception:
        pass

    alert: dict[str, Any] | None = None
    if ctx.send_alerts:
        now = time.time()
        dedup_key = event_id
        dedup_hit = False
        async with ctx.runtime.get_dedup_lock():
            for key, ts in list(ctx.runtime.dedup_cache.items()):
                if now - ts >= ctx.dedup_ttl:
                    ctx.runtime.dedup_cache.pop(key, None)
            if dedup_key in ctx.runtime.dedup_cache:
                dedup_hit = True
            else:
                ctx.runtime.dedup_cache[dedup_key] = now
        if not dedup_hit:
            alert = {
                'id': event_id,
                'host': event.get('host'),
                'verdict': sanitized['verdict'],
                'score': sanitized['score'],
                'rules': rules,
                'ts': now,
                'tenant_id': ctx.tenant_id or os.getenv('DEFAULT_TENANT','default'),
            }
    return processed_event, alert


@app.post('/api/v1/endpoints/log_batch', summary='Ingest endpoint telemetry events')  # type: ignore[misc]
async def log_batch(payload: LogBatchRequest) -> dict[str, Any]:
    """Process endpoint events, optionally emit alerts, and feed decision caches."""
    runtime = _RUNTIME
    nx_enabled, _ = _configure_nx_tracking(runtime)
    dedup_ttl = float(os.getenv('ALERT_DEDUP_TTL_SECONDS', '30'))
    ctx = LogBatchContext(
        runtime=runtime,
        include_rules=payload.include_rules,
        classify=payload.classify,
        send_alerts=payload.send_alerts,
        tenant_id=payload.tenant_id,
        nx_enabled=nx_enabled,
        dedup_ttl=dedup_ttl,
    )

    accepted = 0
    alerts_emitted = 0
    processed_events: list[dict[str, Any]] = []
    errors: list[str] = []

    # Optional field allowlist for export (comma-separated env)
    allowlist_raw = os.getenv('EVIDENCE_FIELD_ALLOWLIST','')
    allowlist = {f.strip() for f in allowlist_raw.split(',') if f.strip()}
    from core.redaction import scrub_record
    for event_model in payload.events:
        processed, alert = await _process_endpoint_event(event_model, ctx)
        # Redact processed record for response/export except allowlisted fields
        try:
            red = scrub_record(processed)
            if allowlist:
                for k in list(red.keys()):
                    if k not in allowlist and k not in ('id','verdict','score'):
                        # retain minimal surface; strip non-allowlisted extras
                        red.pop(k, None)
            processed_events.append(red)
        except Exception:
            processed_events.append(processed)
        accepted += 1
        if alert:
            append_alert(alert)
            alerts_emitted += 1

    return {
        'accepted': accepted,
        'errors': errors,
        'alerts_emitted': alerts_emitted,
        'buffer_size': len(runtime.sanitized_events),
        'events': processed_events,
    }

# Ensure investigation alias router is included (idempotent if already present)
try:
    app.include_router(_investigation_router)
except Exception:
    pass
try:
    app.include_router(_alerts_router)
except Exception:
    pass
try:
    from .stream_ingest import router as _stream_ingest_router
    app.include_router(_stream_ingest_router)
except Exception:
    pass
try:
    app.include_router(_report_router)
except Exception:
    pass
try:
    app.include_router(_analytics_router)
except Exception:
    pass

# ---------------- Runtime Feature Flags Admin Endpoints ----------------
from fastapi import Body as _Body


class _FlagChange(BaseModel):  # type: ignore[misc]
    name: str
    value: Any
    persist: bool | None = True


@app.get('/api/v1/admin/flags', summary='List effective feature flags (with overrides)')
async def flags_list(request: Request) -> dict[str, Any]:
    await check_admin_token_async(request)
    return {'effective': _flags_snapshot(), 'overrides': _list_overrides()}


@app.post('/api/v1/admin/flags/set', summary='Set/override a feature flag at runtime')
async def flags_set(payload: _FlagChange, request: Request) -> dict[str, Any]:
    await check_admin_token_async(request)
    # best-effort audit
    try:
        user = audit_user(request=request)
        audit_emit('flag_set', user, {'name': payload.name, 'value': payload.value, 'persist': bool(payload.persist)})
    except Exception:
        pass
    _set_flag(payload.name, payload.value, persist=bool(payload.persist))
    return {'ok': True, 'name': payload.name, 'value': _get_flag(payload.name)}


@app.delete('/api/v1/admin/flags/{name}', summary='Clear a runtime feature flag override')
async def flags_clear(name: str, request: Request, persist: bool | None = True) -> dict[str, Any]:
    await check_admin_token_async(request)
    try:
        user = audit_user(request=request)
        audit_emit('flag_clear', user, {'name': name, 'persist': bool(persist)})
    except Exception:
        pass
    _clear_flag(name, persist=bool(persist))
    return {'ok': True, 'name': name, 'value': _get_flag(name)}

@app.get('/api/v1/decisions/{event_id}/explain')  # type: ignore[misc]
def explain_decision(event_id: str) -> dict[str, Any]:
    decision = DECISION_CACHE.get(event_id)
    if not decision:
        raise HTTPException(status_code=404, detail='decision_not_found')
    factors = list(getattr(decision, 'factors', []) or [])
    try:
        from core.mappings import mitre_stride
        stride_tags = mitre_stride.map_factors(factors)
    except Exception as exc:
        LOGGER.debug('Failed to map MITRE stride factors: %s', exc, exc_info=exc)
        stride_tags = []
    factor_payload = [{'name': f, 'weight': None, 'weight_decayed': None} for f in factors]
    return {
        'event_id': event_id,
        'verdict': getattr(decision, 'verdict', 'UNKNOWN'),
        'confidence': getattr(decision, 'confidence', 0.0),
        'factors': factor_payload,
        'mitre_stride_tags': stride_tags,
    }

@app.get('/api/v1/decisions/{event_id}/threat_model')  # type: ignore[misc]
def decision_threat_model(event_id: str) -> dict[str, Any]:
    dec = DECISION_CACHE.get(event_id)
    if not dec:
        raise HTTPException(status_code=404, detail='decision_not_found')
    factors = list(getattr(dec,'factors',[]) or [])
    model = aggregate_threat_model(factors)
    return {
        'event_id': event_id,
        'factors_count': len(factors),
        **model
    }

@app.get('/api/v1/decisions/recent', summary='Recent decisions persisted in database')  # type: ignore[misc]
async def decisions_recent(limit: int = 50, tenant_id: str | None = None, auth=Depends(require_scopes('factors.search'))) -> dict[str, Any]:
    adapter = getattr(db_manager, 'adapter', None)
    rows: list[dict[str, Any]] = []
    if adapter and hasattr(adapter, 'pool'):
        # Postgres path
        try:
            async with adapter.pool.acquire() as conn:
                q = "SELECT id, event_id, verdict, confidence, reasons, tenant_id, timestamp FROM decisions"
                clauses = []
                params: list[Any] = []
                if tenant_id:
                    clauses.append("tenant_id=$1")
                    params.append(tenant_id)
                order = " ORDER BY timestamp DESC LIMIT %d" % int(limit)
                if clauses:
                    q += " WHERE " + " AND ".join(clauses)
                q += order
                recs = await conn.fetch(q, *params)
                for r in recs:
                    rows.append({
                        'id': r['id'],
                        'event_id': r['event_id'],
                        'verdict': r['verdict'],
                        'confidence': float(r['confidence']) if r['confidence'] is not None else None,
                        'reasons': r['reasons'],
                        'tenant_id': r['tenant_id'],
                        'ts': getattr(r.get('timestamp',''), 'isoformat', lambda: None)()
                    })
        except Exception:
            rows = []
    elif adapter and hasattr(adapter, 'connection'):
        # SQLite path
        try:
            conn = adapter.connection
            base = "SELECT id, event_id, verdict, confidence, reasons, tenant_id, timestamp FROM decisions"
            clauses = []
            params: list[Any] = []
            if tenant_id:
                clauses.append("tenant_id=?")
                params.append(tenant_id)
            if clauses:
                base += " WHERE " + " AND ".join(clauses)
            base += " ORDER BY timestamp DESC LIMIT ?"
            params.append(int(limit))
            cur = await conn.execute(base, tuple(params))
            recs = await cur.fetchall()
            for r in recs:
                rows.append({
                    'id': r[0],
                    'event_id': r[1],
                    'verdict': r[2],
                    'confidence': float(r[3]) if r[3] is not None else None,
                    'reasons': r[4],
                    'tenant_id': r[5],
                    'ts': r[6]
                })
        except Exception:
            rows = []
    else:
        # Fallback to in-memory cache slice
        rows = []
        for dec in list(DECISION_CACHE.values())[-limit:][::-1]:
            rows.append({
                'id': getattr(dec, 'event_id', None) or dec.get('event_id'),
                'event_id': getattr(dec, 'event_id', None) or dec.get('event_id'),
                'verdict': getattr(dec, 'verdict', None) or dec.get('verdict'),
                'confidence': getattr(dec, 'confidence', None) or dec.get('confidence'),
                'reasons': getattr(dec, 'factors', None) or dec.get('factors'),
                'tenant_id': getattr(dec, 'tenant_id', None) or dec.get('tenant_id'),
                'ts': getattr(dec, 'timestamp', None) or dec.get('ts')
            })
    return {'decisions': rows, 'count': len(rows), 'tenant_id': tenant_id}

@app.get('/api/v1/health', summary='Platform health & metrics presence')  # type: ignore[misc]
async def platform_health() -> dict[str, Any]:
    health: dict[str, Any] = {'status': 'ok'}
    # Regex metrics
    regex_metrics = ['regex_patterns_attempted_total','regex_patterns_completed_total','regex_patterns_timed_out_total','hunt_regex_timeouts_total']
    present = []
    try:
        from prometheus_client import REGISTRY as GREG
        existing = {fam.name for fam in GREG.collect()}  # type: ignore
        present = [m for m in regex_metrics if m in existing]
    except Exception:
        existing = set()
    health['regex_metrics_present'] = present
    health['regex_metrics_expected'] = regex_metrics
    # Baseline cache metrics
    baseline_metrics = ['baseline_cache_hits_total','baseline_cache_misses_total','domain_distinct_current']
    baseline_present = [m for m in baseline_metrics if m in existing]
    health['baseline_metrics_present'] = baseline_present
    # DB health
    try:
        dbh = await db_manager.health_check()
        health['database'] = dbh
    except Exception:
        health['database'] = {'status':'error'}
    # In-memory decision cache size
    try:
        health['decision_cache_size'] = len(DECISION_CACHE)
    except Exception:
        health['decision_cache_size'] = None
    # Baseline store size
    try:
        from core.baseline_service import BASELINES as _B
        health['baseline_store_size'] = await _B.size()
    except Exception:
        health['baseline_store_size'] = None
        # Cluster metrics presence
        cluster_metrics = ['alerts_clusters_total','alerts_cluster_size_histogram_seconds']
        cluster_present = [m for m in cluster_metrics if m in existing]
        health['cluster_metrics_present'] = cluster_present
        health['cluster_metrics_expected'] = cluster_metrics
    return health

# ---------------- Baselines Service Endpoints ----------------
class BaselineBatchRequest(BaseModel):  # type: ignore[misc]
    items: list[dict[str, Any]]

@app.get('/api/v1/baselines/entity/{entity_type}/{entity_id}/{metric}', summary='Fetch baseline stats & z-score (optional current value)')  # type: ignore[misc]
async def baseline_entity(entity_type: str, entity_id: str, metric: str, current_value: float | None = None, auth=Depends(require_scopes('factors.search'))) -> dict[str, Any]:
    import time as _t
    _start = _t.perf_counter()
    res = await BASELINES.get_z(entity_type, entity_id, metric, current_value)
    try: _baseline_endpoint_latency.labels(endpoint='entity').observe(_t.perf_counter()-_start)
    except Exception: pass
    return {'entity_type': entity_type, 'entity_id': entity_id, 'metric': metric, **res}

@app.post('/api/v1/baselines/zscores', summary='Batch baseline z-scores')  # type: ignore[misc]
async def baseline_batch(payload: BaselineBatchRequest, auth=Depends(require_scopes('factors.search'))) -> dict[str, Any]:
    import time as _t
    _start = _t.perf_counter()
    results = await BASELINES.batch_get_z(payload.items)
    try: _baseline_endpoint_latency.labels(endpoint='batch').observe(_t.perf_counter()-_start)
    except Exception: pass
    return {'results': results, 'count': len(results)}

@app.delete('/api/v1/baselines/entity/{entity_type}/{entity_id}/{metric}', summary='Delete a specific baseline record')  # type: ignore[misc]
async def baseline_delete(entity_type: str, entity_id: str, metric: str, auth=Depends(require_scopes('factors.search'))) -> dict[str, Any]:
    removed = await BASELINES.delete(entity_type, entity_id, metric)
    return {'deleted': removed, 'entity_type': entity_type, 'entity_id': entity_id, 'metric': metric}

@app.post('/api/v1/threat_modeling/reload', summary='Manually trigger scenario reload (if hot-reload enabled)')  # type: ignore[misc]
def manual_scenario_reload(request: Request) -> dict[str, Any]:
    check_admin_token(request)
    from core.threat_modeling import reload_watcher
    watcher = reload_watcher.ensure_watcher()
    if watcher is None:
        return {'status': 'disabled'}
    # Force reload by bumping mtime logic: call internal _do_reload directly
    try:
        watcher._do_reload()
        return {'status': 'reloaded', 'reload_count': watcher.reload_count, 'failure_count': watcher.failure_count}
    except Exception as exc:
        return {'status': 'error', 'error': str(exc)}

@app.get('/api/v1/metrics/self_test', summary='Validate presence of expected metrics names')  # type: ignore[misc]
def metrics_self_test() -> dict[str, Any]:
    try:
        from prometheus_client import REGISTRY as GLOBAL_REG
    except Exception:
        GLOBAL_REG = None
    names_present = set()
    try:
        if GLOBAL_REG:
            for fam in GLOBAL_REG.collect():
                names_present.add(fam.name)
    except Exception:
        pass
    missing = []
    for name,_ in expected_metrics().items():
        if name not in names_present:
            missing.append(name)
    return {
        'expected_total': len(expected_metrics()),
        'present': len(expected_metrics()) - len(missing),
        'missing': missing
    }


@app.get('/api/v1/events/sanitized', summary='Retrieve recently sanitized events')  # type: ignore[misc]
async def events_sanitized(limit: int = 50) -> dict[str, Any]:
    """Return the most recent sanitized events for debugging clients."""
    runtime = _RUNTIME
    limit = max(0, min(limit, len(runtime.sanitized_events)))
    async with runtime.get_sanitized_lock():
        items = list(runtime.sanitized_events)[:limit]
    return {'events': items, 'count': len(items)}


@app.get('/api/v1/clusters/{cluster_id}', summary='Fetch cluster details')  # type: ignore[misc]
async def cluster_details(cluster_id: str) -> dict[str, Any]:
    try:
        info = await CLUSTERING.get(cluster_id)
        if not info:
            raise HTTPException(status_code=404, detail='cluster_not_found')
        return {'cluster': info}
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.debug('Cluster lookup failed: %s', exc, exc_info=exc)
        raise HTTPException(status_code=500, detail='cluster_lookup_failed')


@app.get('/api/v1/decisions/{event_id}/risk', summary='Fetch composed risk explainability for a decision')  # type: ignore[misc]
async def decision_risk_explain(event_id: str) -> dict[str, Any]:
    try:
        cache = globals().get('DECISION_CACHE')
        dec = None
        if isinstance(cache, dict):
            dec = cache.get(event_id)
        else:
            dec = None
        if not dec:
            raise HTTPException(status_code=404, detail='decision_not_found')
        # If risk payload already present, return it
        if 'risk_score' in dec and 'risk_breakdown' in dec:
            return {'event_id': event_id, 'risk_score': dec.get('risk_score'), 'breakdown': dec.get('risk_breakdown'), 'method': dec.get('risk_method')}
        # Otherwise compute on-demand
        try:
            from core.risk_score import compose_risk_score
            rs = await compose_risk_score(dec)
            return {'event_id': event_id, 'risk_score': rs.get('score'), 'breakdown': rs.get('breakdown'), 'method': rs.get('method')}
        except Exception as exc:
            LOGGER.debug('Risk explain failed: %s', exc, exc_info=exc)
            raise HTTPException(status_code=500, detail='risk_explain_failed')
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.debug('Decision risk lookup failed: %s', exc, exc_info=exc)
        raise HTTPException(status_code=500, detail='decision_lookup_failed')

@app.get('/api/v1/risk/{event_id}/explain', summary='Detailed risk component explanation')  # type: ignore[misc]
async def risk_explain_v2(event_id: str) -> dict[str, Any]:
    """Return extended risk explainability including variance & confidence interval.

    Response schema:
      {
        event_id, score, raw_score, method, breakdown: [...], variance, ci95: [low, high], confidence,
        mean_contribution
      }
    """
    try:
        cache = globals().get('DECISION_CACHE')
        dec = cache.get(event_id) if isinstance(cache, dict) else None
        if not dec:
            raise HTTPException(status_code=404, detail='decision_not_found')
        # If already enriched with new fields, return directly
        if 'risk_score' in dec and 'risk_breakdown' in dec:
            return {
                'event_id': event_id,
                'score': dec.get('risk_score'),
                'raw_score': dec.get('risk_raw_score'),
                'method': dec.get('risk_method'),
                'breakdown': dec.get('risk_breakdown'),
                'variance': dec.get('risk_variance'),
                'ci95': dec.get('risk_ci95'),
                'confidence': dec.get('confidence'),
            }
        # Otherwise compose on-demand
        from core.risk_score import compose_risk_score
        rs = await compose_risk_score(dec)
        return {
            'event_id': event_id,
            'score': rs.get('score'),
            'raw_score': rs.get('raw_score'),
            'method': rs.get('method'),
            'breakdown': rs.get('breakdown'),
            'variance': rs.get('variance'),
            'ci95': rs.get('ci95'),
            'confidence': rs.get('confidence'),
        }
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.debug('Risk explain v2 failed: %s', exc, exc_info=exc)
        raise HTTPException(status_code=500, detail='risk_explain_failed')

def track_alert_event(timestamp: float | None) -> None:
    # placeholder for future tracking hooks; explicitly typed to satisfy mypy
    return None

# --------------------------- Labeling & Quality Endpoints (Stage 10) ---------------------------
from fastapi import Body

class LabelPayload(BaseModel):  # type: ignore[misc]
    label: str
    source: str | None = None
    reviewer: str | None = None

@app.post('/api/v1/decisions/{event_id}/label', summary='Apply an analyst/automated label to a decision')  # type: ignore[misc]
async def label_decision(event_id: str, payload: LabelPayload, request: Request, auth=Depends(require_scopes('feedback.write'))):  # type: ignore[misc]
    label = payload.label.lower().strip()
    if label not in VALID_LABELS:
        raise HTTPException(status_code=400, detail='invalid_label')
    # Retrieve attribution snapshot for factors to update stats
    snap = FACTOR_ATTRIBUTIONS.get(event_id)
    if not snap:
        # attempt to fallback to existing decision risk breakdown to construct a synthetic snapshot
        cache = globals().get('DECISION_CACHE')
        dec = cache.get(event_id) if isinstance(cache, dict) else None
        if dec and dec.get('risk_breakdown'):
            factors = [e.get('factor') for e in dec['risk_breakdown'] if isinstance(e.get('factor'), str)]
        else:
            factors = []
    else:
        factors = list(snap.factors)
    # Store label
    try:
        rec = LABELS.add_label(event_id, label, payload.source or 'api', reviewer=payload.reviewer)
    except ValueError:
        raise HTTPException(status_code=400, detail='invalid_label')
    # Update rolling stats
    from time import time as _now
    FACTOR_STATS.update_from_label(factors, label, _now())
    try:
        # audit label writes
        user = audit_user(request=request, auth=auth)
        audit_emit('label_written', user, {'event_id': event_id, 'label': label, 'source': payload.source, 'reviewer': payload.reviewer})
    except Exception:
        pass
    return {'status': 'ok', 'event_id': event_id, 'label': label, 'factors_count': len(factors)}

@app.get('/api/v1/quality/factors/summary', summary='Summarize factor quality & promotion states')  # type: ignore[misc]
async def factors_quality_summary(auth=Depends(require_scopes('factors.search'))):  # type: ignore[misc]
    return {'factors': FACTOR_STATS.summary(), 'count': len(FACTOR_STATS.summary())}


@app.get('/api/v1/quality/factors/status/{factor}', summary='Get factor state and stats')  # type: ignore[misc]
async def factor_status(factor: str, auth=Depends(require_scopes('factors.search'))):  # type: ignore[misc]
    st = FACTOR_STATS.get(factor)
    if not st:
        raise HTTPException(status_code=404, detail='factor_not_found')
    return {
        'factor': st.factor,
        'tp': st.tp,
        'fp': st.fp,
        'total': st.total(),
        'precision': st.precision(),
        'state': st.state(),
        'last_label_ts': st.last_label_ts,
    }

@app.get('/api/v1/risk/calibration/export', summary='Export labeled samples for calibration')  # type: ignore[misc]
async def calibration_export(limit: int = 1000, auth=Depends(require_scopes('feedback.write'))):  # type: ignore[misc]
    """Produce dataset rows: event_id, raw_score, score, label (tp/fp/benign only), top_factors.

    Only includes events with at least one qualifying label.
    """
    rows = []
    qualifying = {'tp','fp','benign'}
    for snap in FACTOR_ATTRIBUTIONS.recent(limit * 2):  # oversample then trim
        labels = LABELS.get(snap.event_id)
        lab = None
        for l in reversed(labels):  # prefer most recent qualifying
            if l.label in qualifying:
                lab = l.label
                break
        if not lab:
            continue
        # choose top factors (up to 5 by contribution order already preserved in snapshot breakdown)
        top_factors = []
        for b in snap.breakdown:
            f = b.get('factor')
            if isinstance(f, str) and not f.startswith('risk:'):
                top_factors.append(f)
            if len(top_factors) >= 5:
                break
        rows.append({
            'event_id': snap.event_id,
            'raw_score': snap.raw_score,
            'score': snap.score,
            'label': lab,
            'top_factors': top_factors,
        })
        if len(rows) >= limit:
            break
    return {'samples': rows, 'count': len(rows)}


@app.get('/api/v1/risk/calibration/last', summary='Return last recalibration proposal')  # type: ignore[misc]
async def calibration_last(auth=Depends(require_scopes('factors.search'))):  # type: ignore[misc]
    try:
        from core.recalibrator import get_last_proposal
        p = get_last_proposal()
        if not p:
            return {'proposal': None}
        return {'proposal': p}
    except Exception:
        raise HTTPException(status_code=500, detail='recalibrator_unavailable')


@app.get('/api/v1/risk/calibration/history', summary='Return recent recalibration proposals')  # type: ignore[misc]
async def calibration_history(limit: int = 50, auth=Depends(require_scopes('factors.search'))):  # type: ignore[misc]
    try:
        from core.recalibrator import get_proposal_history
        return {'history': get_proposal_history(limit), 'count': len(get_proposal_history(limit))}
    except Exception:
        raise HTTPException(status_code=500, detail='recalibrator_unavailable')


@app.post('/api/v1/risk/calibration/proposals/{ts}/accept', summary='Accept a recalibration proposal')  # type: ignore[misc]
async def accept_proposal(ts: float, request: Request, auth=Depends(require_scopes('factors.search'))):  # type: ignore[misc]
    try:
        from core.recalibrator import mark_proposal
        ok = mark_proposal(ts, accept=True)
        if not ok:
            raise HTTPException(status_code=404, detail='proposal_not_found')
        try:
            user = audit_user(request=request, auth=auth)
            audit_emit('calibration_accept', user, {'ts': ts})
        except Exception:
            pass
        return {'status': 'accepted', 'ts': ts}
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.debug('Accept proposal failed: %s', exc, exc_info=exc)
        raise HTTPException(status_code=500, detail='accept_failed')


@app.post('/api/v1/risk/calibration/proposals/{ts}/reject', summary='Reject a recalibration proposal')  # type: ignore[misc]
async def reject_proposal(ts: float, request: Request, auth=Depends(require_scopes('factors.search'))):  # type: ignore[misc]
    try:
        from core.recalibrator import mark_proposal
        ok = mark_proposal(ts, accept=False)
        if not ok:
            raise HTTPException(status_code=404, detail='proposal_not_found')
        try:
            user = audit_user(request=request, auth=auth)
            audit_emit('calibration_reject', user, {'ts': ts})
        except Exception:
            pass
        return {'status': 'rejected', 'ts': ts}
    except HTTPException:
        raise
    except Exception as exc:
        LOGGER.debug('Reject proposal failed: %s', exc, exc_info=exc)
        raise HTTPException(status_code=500, detail='reject_failed')


@app.post('/api/v1/risk/calibration/auto_accept', summary='Evaluate auto-accept policy and optionally apply')  # type: ignore[misc]
async def calibration_auto_accept(apply: bool = False, min_samples: int = 50, min_ll_delta: float = 1.0, request: Request = None, auth=Depends(require_scopes('factors.search'))):  # type: ignore[misc]
    try:
        from core.recalibrator import evaluate_auto_accept, get_last_proposal, mark_proposal
        res = evaluate_auto_accept(min_samples=min_samples, min_ll_delta=min_ll_delta)
        if apply and res.get('ok'):
            last = get_last_proposal()
            if last:
                ok = mark_proposal(last.get('ts'), accept=True)
                res['applied'] = bool(ok)
        try:
            user = audit_user(request=request, auth=auth)
            audit_emit('calibration_auto_accept', user, {'apply': apply, 'min_samples': min_samples, 'min_ll_delta': min_ll_delta, 'result_ok': bool(res.get('ok'))})
        except Exception:
            pass
        return res
    except Exception as exc:
        LOGGER.debug('Auto-accept evaluation failed: %s', exc, exc_info=exc)
        raise HTTPException(status_code=500, detail='auto_accept_failed')


@app.get('/risk/calibration/report', summary='Human-readable calibration report (HTML)')  # type: ignore[misc]
async def calibration_report(request: Request, auth=Depends(require_scopes('factors.search'))):  # type: ignore[misc]
    try:
        from core.recalibrator import get_last_proposal
        p = get_last_proposal()
        if not p:
            return HTMLResponse('<html><body><h3>No proposals yet</h3></body></html>')
        # Build a tiny HTML summary
        html = ['<html><body>']
        html.append(f"<h2>Last Proposal @ {p.get('ts')}</h2>")
        html.append(f"<p>k={p.get('k')}, x0={p.get('x0')}, samples={p.get('samples')}, ks={p.get('ks_tp_fp')}</p>")
        html.append('<h3>Top TP factors</h3><ul>')
        for f,c in sorted(p.get('tp_factor_counts', {}).items(), key=lambda x:x[1], reverse=True)[:10]:
            html.append(f'<li>{f}: {c}</li>')
        html.append('</ul><h3>Top FP factors</h3><ul>')
        for f,c in sorted(p.get('fp_factor_counts', {}).items(), key=lambda x:x[1], reverse=True)[:10]:
            html.append(f'<li>{f}: {c}</li>')
        html.append('</ul></body></html>')
        try:
            user = audit_user(request=request, auth=auth)
            audit_emit('calibration_report_view', user, {'ts': p.get('ts')})
        except Exception:
            pass
        return HTMLResponse('\n'.join(html))
    except Exception as exc:
        LOGGER.debug('Report render failed: %s', exc, exc_info=exc)
        raise HTTPException(status_code=500, detail='report_failed')

# --------------------------- SSE Decision Recording ---------------------------
async def _record_decision_async(event_id: str, verdict: str, confidence: float, factors: list[str], meta: dict[str, Any] | None = None) -> None:
    """Async path for recording decisions: compose risk, publish SSE, persist to DB."""
    try:
        dec = {
            'event_id': event_id,
            'id': event_id,
            'verdict': verdict,
            'confidence': confidence,
            'factors': list(factors) if isinstance(factors, list) else [],
            'ts': time.time(),
        }
        # Scenario enrichment (PASTA Phase 1) + risk factor injection
        try:
            from core.threat_modeling.scenario_engine import ENGINE as _SCEN_ENGINE
            scenarios = _SCEN_ENGINE.evaluate(dec['factors']) if _SCEN_ENGINE.enabled else []
            if scenarios:
                dec['scenarios'] = scenarios
                # Risk thresholds (environment configurable)
                try:
                    high_thr = float(os.getenv('SCENARIO_HIGH_RISK','3.5') or 3.5)
                except Exception:
                    high_thr = 3.5
                try:
                    critical_thr = float(os.getenv('SCENARIO_CRITICAL_RISK','4.2') or 4.2)
                except Exception:
                    critical_thr = 4.2
                added_any = False
                for s in scenarios:
                    if s.get('status') != 'observed':
                        continue
                    cr = s.get('composite_risk')
                    if not isinstance(cr,(int,float)):
                        continue
                    sid = s.get('id','').lower()
                    if cr >= critical_thr:
                        factors.append(f'scenario:critical:{sid}')
                        added_any = True
                    elif cr >= high_thr:
                        factors.append(f'scenario:high:{sid}')
                        added_any = True
                if added_any:
                    # persist updated factors into dec
                    dec['factors'] = factors
        except Exception:
            # Silent failure – enrichment is best-effort
            pass
        # Insert / rotate cache
        cache = globals().get('DECISION_CACHE')
        if isinstance(cache, dict):
            cache[event_id] = dec
            # trim if very large
            if len(cache) > 5000:
                # remove oldest arbitrary (not ordered) – convert to list
                for k in list(cache.keys())[:100]:
                    cache.pop(k, None)
        # Fire SSE publish (async)
        try:
            from .decisions_stream import _RECENT_DECISIONS
            _RECENT_DECISIONS.append(dec)
        except Exception:
            pass
        try:
            await _publish_decision(dec)
        except Exception:
            # best-effort: don't break pipeline
            pass
        # Compose a risk score and persist in background (best-effort).
        try:
            from core.risk_score import compose_risk_score

            async def _compose_and_persist(decision_obj, meta_obj=None):
                # merge meta
                if meta_obj:
                    decision_obj.update(meta_obj)
                # Derive a simple novelty score from first cluster if available
                try:
                    if 'clusters' in decision_obj and decision_obj['clusters']:
                        first_cl = decision_obj['clusters'][0]
                        nv = first_cl.get('novelty')
                        if isinstance(nv,(int,float)):
                            decision_obj['novelty_score'] = float(nv)
                except Exception:
                    pass
                try:
                    rs = await compose_risk_score(decision_obj, tenant_id=decision_obj.get('tenant_id'))
                    if rs:
                        decision_obj['risk_score'] = float(rs.get('score') or 0.0)
                        decision_obj['risk_breakdown'] = rs.get('breakdown')
                        decision_obj['risk_method'] = rs.get('method')
                        # New explainability stats
                        if 'variance' in rs:
                            decision_obj['risk_variance'] = rs.get('variance')
                        if 'ci95' in rs:
                            decision_obj['risk_ci95'] = rs.get('ci95')
                        if 'raw_score' in rs:
                            decision_obj['risk_raw_score'] = rs.get('raw_score')
                        # Factor attribution snapshot (Stage 10)
                        try:
                            from core.factor_attribution_store import FACTOR_ATTRIBUTIONS, FactorAttributionSnapshot
                            # Extract raw factor list from breakdown excluding pure meta markers with zero contribution (keep penalties)
                            bd = rs.get('breakdown') or []
                            factor_list = []
                            for entry in bd:
                                f = entry.get('factor')
                                if not isinstance(f, str):
                                    continue
                                # Skip meta factors like risk:high with no contribution to reduce noise
                                if f.startswith('risk:') and float(entry.get('contribution') or 0.0) == 0.0:
                                    continue
                                factor_list.append(f)
                            snap = FactorAttributionSnapshot(
                                event_id=decision_obj.get('event_id') or decision_obj.get('id') or 'unknown',
                                ts=decision_obj.get('ts') or time.time(),
                                factors=factor_list,
                                breakdown=bd,
                                score=float(rs.get('score') or 0.0),
                                raw_score=rs.get('raw_score'),
                                confidence=decision_obj.get('confidence'),
                                variance=rs.get('variance'),
                                ci95=tuple(rs.get('ci95')) if rs.get('ci95') else None,
                            )
                            FACTOR_ATTRIBUTIONS.add_snapshot(snap)
                        except Exception:
                            # best-effort; do not disrupt pipeline
                            pass
                except Exception:
                    pass
                # Optional auto-escalation after composition
                try:
                    auto_flag = os.getenv('RISK_AUTO_ESCALATE','0').lower() in {'1','true','yes'}
                    if auto_flag and decision_obj.get('risk_score') is not None:
                        try:
                            thr = float(os.getenv('RISK_AUTO_ESCALATE_THRESHOLD','0.8') or 0.8)
                        except Exception:
                            thr = 0.8
                        if decision_obj['risk_score'] >= thr and decision_obj.get('verdict','').upper() != 'MALICIOUS':
                            decision_obj['verdict'] = 'SUSPICIOUS' if decision_obj['risk_score'] < 0.95 else 'MALICIOUS'
                except Exception:
                    pass
                # persistence (best-effort)
                try:
                    decisions_repo = globals().get('decisions_repo')
                    payload = decision_obj.copy()
                    try:
                        _PERSISTED_DECISIONS.append(payload)
                    except Exception:
                        pass
                    if decisions_repo and callable(getattr(decisions_repo, 'persist', None)):
                        try:
                            maybe = decisions_repo.persist(payload)
                            if asyncio.iscoroutine(maybe):
                                await maybe
                        except Exception:
                            # best-effort fallback: ignore
                            pass
                except Exception:
                    pass

            # run composition and persist in this async context
            try:
                await _compose_and_persist(dec, meta)
            except Exception:
                pass
        except Exception:
            pass
    except Exception:
        try:
            LOGGER.exception('_record_decision_async failed')
        except Exception:
            pass


def _record_decision(event_id: str, verdict: str, confidence: float, factors: list[str], meta: dict[str, Any] | None = None) -> None:
    """Compatibility sync wrapper that calls the async record function.

    If called inside an event loop, schedule the async task; otherwise run to completion.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        loop.create_task(_record_decision_async(event_id, verdict, confidence, factors, meta))
    else:
        try:
            asyncio.run(_record_decision_async(event_id, verdict, confidence, factors, meta))
        except Exception:
            pass
