from __future__ import annotations

import time
import os
from typing import Any, Dict

from fastapi import APIRouter, Request, HTTPException, Header
import sqlite3, threading, time

# Simple audit DB for dispatch persistence
_AUDIT_DB = os.getenv('DISPATCH_AUDIT_DB', os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'dispatch_audit.db')))
_AUDIT_LOCK = threading.Lock()

def _ensure_audit_db():
    os.makedirs(os.path.dirname(_AUDIT_DB), exist_ok=True)
    with _AUDIT_LOCK:
        conn = sqlite3.connect(_AUDIT_DB)
        try:
            cur = conn.cursor()
            cur.execute('''
            CREATE TABLE IF NOT EXISTS dispatch_audit (
                id TEXT PRIMARY KEY,
                tenant_id TEXT,
                endpoint TEXT,
                payload TEXT,
                status TEXT,
                attempts INTEGER DEFAULT 0,
                last_attempt REAL
            )
            ''')
            conn.commit()
        finally:
            conn.close()


def record_audit(aid: str, tenant_id: str, endpoint: str, payload: str, status: str = 'pending'):
    _ensure_audit_db()
    now = time.time()
    with _AUDIT_LOCK:
        conn = sqlite3.connect(_AUDIT_DB)
        try:
            cur = conn.cursor()
            cur.execute('INSERT OR REPLACE INTO dispatch_audit(id, tenant_id, endpoint, payload, status, attempts, last_attempt) VALUES(?,?,?,?,?, COALESCE((SELECT attempts FROM dispatch_audit WHERE id=?),0)+1,?)', (aid, tenant_id, endpoint, payload, status, aid, now))
            conn.commit()
        finally:
            conn.close()

from src.api.pull_endpoints import identity_pull, edr_process_tree_pull, dns_lookup_pull
from src.security.auth import require_api_key
import src.api.metrics_init as metrics
from src.api.runtime_state import get_tenant_runtime
from src.api.dispatch_outbox import enqueue, get_pending, mark_attempt, mark_done

router = APIRouter(prefix="/api/v1/gaps", tags=["gaps"])


@router.post('/dispatch')
async def dispatch_ask(payload: Dict[str, Any], request: Request, _auth = require_api_key):
    """Server-side dispatcher: accept a single ask object, call the matching pull
    endpoint in-process, increment dispatch metrics, and optionally persist
    the action against an incident if `incident_id` is provided in the payload.
    """
    try:
        metrics.ensure_metrics()
    except Exception:
        pass
    tenant = request.headers.get('x-tenant-id') or os.getenv('DEFAULT_TENANT','default')
    ask = payload.get('ask') or payload
    if not isinstance(ask, dict):
        raise HTTPException(status_code=400, detail='ask_object_required')
    api = ask.get('api') or {}
    endpoint = api.get('endpoint') or ask.get('source')
    start = time.time()
    status = 'error'
    # Pre-record audit entry to ensure idempotency and that the audit table exists
    try:
        aid = payload.get('dispatch_id') or payload.get('ask', {}).get('id') or None
        if aid:
            try:
                record_audit(str(aid), tenant, str(endpoint or 'unknown'), str(payload), 'pending')
            except Exception:
                pass
    except Exception:
        pass
    try:
        # route to in-process pull handlers by endpoint keyword with retries
        max_attempts = 3
        attempt = 0
        last_exc = None
        while attempt < max_attempts:
            attempt += 1
            try:
                if 'identity' in str(endpoint).lower() or endpoint == 'identity_auth_logs':
                    res = await identity_pull({'users': ask.get('users') or [], 'start': ask.get('start'), 'end': ask.get('end'), 'ttl_seconds': ask.get('ttl_seconds', 1800)}, request)
                elif 'edr' in str(endpoint).lower() or 'process_tree' in str(endpoint).lower():
                    res = await edr_process_tree_pull({'hosts': ask.get('hosts') or [], 'center': ask.get('center'), 'window_minutes': ask.get('window_minutes', 30), 'ttl_seconds': ask.get('ttl_seconds', 1800)}, request)
                elif 'dns' in str(endpoint).lower() or 'dns_query' in str(endpoint).lower():
                    res = await dns_lookup_pull({'domains': ask.get('domains') or [], 'hosts': ask.get('hosts') or [], 'start': ask.get('start'), 'end': ask.get('end'), 'ttl_seconds': ask.get('ttl_seconds', 1800)}, request)
                else:
                    raise HTTPException(status_code=400, detail='unsupported_endpoint')
                # success
                last_exc = None
                break
            except HTTPException as exc:
                # allow unsupported endpoints to fall through into outbox enqueue
                if exc.status_code == 400 and str(exc.detail) == 'unsupported_endpoint':
                    last_exc = exc
                    break
                # don't retry for other client errors
                raise
            except Exception as e:
                last_exc = e
                # small backoff
                try:
                    time.sleep(0.05 * attempt)
                except Exception:
                    pass
        if last_exc:
            # exhausted attempts: enqueue to durable outbox for background retry
            try:
                dispatch_id = payload.get('dispatch_id') or payload.get('ask', {}).get('id') or f'outbox-{int(time.time()*1000)}'
                enqueue(str(dispatch_id), tenant, str(endpoint or 'unknown'), {'payload': payload})
            except Exception:
                pass
            raise last_exc
        status = 'ok'
        try:
            # mark audit as ok
            aid = payload.get('dispatch_id') or payload.get('ask', {}).get('id') or None
            if aid:
                try:
                    record_audit(str(aid), tenant, str(endpoint or 'unknown'), str(payload), 'ok')
                except Exception:
                    pass
        except Exception:
            pass
        return_payload = {'dispatched': True, 'response': res}
    except HTTPException:
        raise
    except Exception as e:
        return_payload = {'dispatched': False, 'error': str(e)}
    finally:
        # persist audit entry (idempotency support)
        try:
            aid = payload.get('dispatch_id') or payload.get('ask', {}).get('id') or None
            if aid:
                try:
                    record_audit(str(aid), tenant, str(endpoint or 'unknown'), str(payload), status)
                except Exception:
                    pass
        except Exception:
            pass
        # metrics
        try:
            metrics.asks_sent_total.labels(endpoint=endpoint or 'unknown', status=status).inc(1)
        except Exception:
            try:
                metrics.asks_sent_total.labels(str(endpoint or 'unknown'), status).inc(1)
            except Exception:
                pass
        try:
            metrics.asks_dispatch_latency_seconds.labels(endpoint=endpoint or 'unknown').observe(max(0.0, time.time() - start))
        except Exception:
            pass


def start_outbox_worker(loop_delay: float = 1.0, worker_limit: int = 5, max_attempts: int = 5):
    """Start a background thread that will poll the outbox and attempt to re-dispatch entries.
    This is intentionally simple: it looks up pending outbox rows, attempts the in-process dispatch
    by calling the same endpoints as `dispatch_ask` and marks rows done or updates attempt counts.
    """
    def _worker():
        while True:
            try:
                pending = get_pending(limit=worker_limit)
                if not pending:
                    time.sleep(loop_delay)
                    continue
                for row in pending:
                    did = row.get('id')
                    tenant = row.get('tenant_id')
                    endpoint = row.get('endpoint')
                    try:
                        payload = json.loads(row.get('payload') or '{}')
                    except Exception:
                        payload = {'payload': {}}
                    attempts = row.get('attempts') or 0
                    # attempt in-process call using local test request shim
                    try:
                        # build a fake request with headers
                        from starlette.requests import Request as StarletteRequest
                        from starlette.datastructures import Headers, URL
                        scope = {"type": "http", "method": "POST", "path": endpoint, "headers": [(b'x-tenant-id', tenant.encode())]}
                        fake_req = StarletteRequest(scope)
                        # route dispatch by endpoint similar to dispatch_ask
                        res = None
                        if 'identity' in str(endpoint).lower():
                            res = None
                            # call sync function via identity_pull is async; use asyncio.run if needed
                            import asyncio
                            res = asyncio.get_event_loop().run_until_complete(identity_pull(payload.get('payload', {}), fake_req))
                        elif 'edr' in str(endpoint).lower():
                            import asyncio
                            res = asyncio.get_event_loop().run_until_complete(edr_process_tree_pull(payload.get('payload', {}), fake_req))
                        elif 'dns' in str(endpoint).lower():
                            import asyncio
                            res = asyncio.get_event_loop().run_until_complete(dns_lookup_pull(payload.get('payload', {}), fake_req))
                        else:
                            raise Exception('unsupported_outbox_endpoint')
                        # success
                        mark_done(did)
                    except Exception as e:
                        attempts = (attempts or 0) + 1
                        last_err = str(e)
                        if attempts >= max_attempts:
                            # give up and mark as done to avoid infinite retry; operator might inspect later
                            mark_attempt(did, attempts, last_err, status='failed')
                        else:
                            mark_attempt(did, attempts, last_err, status='pending')
            except Exception:
                try:
                    time.sleep(loop_delay)
                except Exception:
                    pass

    th = threading.Thread(target=_worker, daemon=True)
    th.start()
    return th

    # Optional: persist recommendation action to incident if present
    try:
        iid = payload.get('incident_id') or payload.get('incident')
        if iid and isinstance(iid, str):
            # Call existing incident action handler via internal route
            from src.api.app import app
            # Build a minimal payload to mark as dispatched (status=pending)
            body = {'action_id': ask.get('id') or ask.get('action_id') or ask.get('api',{}).get('id'), 'status': 'pending', 'actor': request.headers.get('x-actor')}
            # call through app router: find handler and call directly
            # Simpler: import GLOBAL_INCIDENTS and update directly if available
            try:
                from src.incidents.aggregator import GLOBAL_INCIDENTS
                if GLOBAL_INCIDENTS:
                    GLOBAL_INCIDENTS.update_recommendation_action(str(iid), str(body.get('action_id') or ''), str(body.get('status') or ''), body.get('actor'))
            except Exception:
                pass
    except Exception:
        pass

    return return_payload
