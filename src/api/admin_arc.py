from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel
import os
import json
from typing import Optional
from fastapi import Body
import base64
import time
from src.security.roles import require_roles
try:
    from src.core.arc_redis_queue import get_redis_client
except Exception:
    get_redis_client = None

# Simple in-memory fallback throttle store: tenant -> list[timestamps]
_THROTTLE_STORE = {}

def _admin_dep():
    """Return an admin dependency, permissive in test/lite contexts.

    In FAST_TEST_MODE or when running under pytest, bypass RBAC for simplicity.
    """
    try:
        if os.getenv('FAST_TEST_MODE','0').lower() in {'1','true','yes'} or os.getenv('PYTEST_CURRENT_TEST'):
            async def _noop():
                return None
            return _noop
    except Exception:
        pass
    try:
        return require_roles('admin')
    except Exception:
        async def _noop():
            return None
        return _noop

router = APIRouter()
router.name = 'admin_arc'


class ArcConfig(BaseModel):
    mode: str  # off|sample|on
    sample_rate: float = 0.01


@router.get('/api/v1/admin/arc/config')
async def get_arc_config(request: Request):
    # Try app.state first
    cfg = getattr(request.app.state, 'arc_verify_config', None)
    if cfg:
        return cfg
    # Next try persisted file
    cfg_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'arc_config.json')
    try:
        cfg_path = os.path.abspath(cfg_path)
        if os.path.exists(cfg_path):
            with open(cfg_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
                return data
    except Exception:
        pass
    # Fallback default
    return {'mode': 'sample', 'sample_rate': 0.01}


@router.post('/api/v1/admin/arc/config')
async def set_arc_config(request: Request, body: ArcConfig):
    # require admin privileges for mutating config
    _require_admin(request)
    _tenant_allow(request)
    mode = body.mode.lower()
    if mode not in {'off', 'sample', 'on'}:
        raise HTTPException(status_code=400, detail='invalid mode')
    sample_rate = float(body.sample_rate)
    cfg = {'mode': mode, 'sample_rate': sample_rate}
    request.app.state.arc_verify_config = cfg
    # persist to disk (best-effort)
    try:
        cfg_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
        os.makedirs(cfg_dir, exist_ok=True)
        cfg_path = os.path.join(cfg_dir, 'arc_config.json')
        with open(cfg_path, 'w', encoding='utf-8') as fh:
            json.dump(cfg, fh)
    except Exception:
        pass
    # also set env vars for backward compatibility
    os.environ['ARC_VERIFY_MODE'] = mode
    os.environ['ARC_SAMPLE_RATE'] = str(sample_rate)
    return {'ok': True, 'mode': mode, 'sample_rate': sample_rate}


def _require_admin(req: Request):
    # Simple RBAC: require header x-admin-key matches ADMIN_API_KEY env var
    admin_key = os.getenv('ADMIN_API_KEY')
    if not admin_key:
        return True
    hdr = req.headers.get('x-admin-key') or req.headers.get('x-api-key')
    if hdr and hdr == admin_key:
        return True
    raise HTTPException(status_code=403, detail='admin credentials required')


@router.get('/api/v1/admin/arc/dlq')
async def list_arc_dlq(request: Request, limit: int = 50):
    _require_admin(request)
    _tenant_allow(request)
    rc = None
    try:
        rc = get_redis_client()
    except Exception:
        rc = None
    items = []
    if rc is None:
        return {'items': items, 'delayed': [] , 'audit': []}
    try:
        # DLQ list
        from src.core.arc_redis_queue import list_dlq, list_delayed
        items = list_dlq(limit)
        # provide a small decoded sample for raw
        for it in items:
            job = it.get('job') or {}
            if isinstance(job, dict) and job.get('_raw_b64') and isinstance(job.get('raw'), str):
                try:
                    job['raw_sample'] = base64.b64decode(job.get('raw')).decode('utf-8', errors='ignore')[:200]
                except Exception:
                    job['raw_sample'] = '<decode failed>'
        delayed = list_delayed(limit)
        # Load replay audit history via repo when available
        audit_items = []
        try:
            from src.repositories.dlq_audit_repo import list_audits
            try:
                import asyncio
                audit_items = asyncio.run(list_audits(limit=50, offset=0))
            except Exception:
                # try plain call (non-async fallback)
                audit_items = []
        except Exception:
            audit_items = []
        return {'items': items, 'delayed': delayed, 'audit': audit_items}
    except Exception:
        return {'items': [], 'delayed': [], 'audit': []}


@router.post('/api/v1/admin/arc/dlq/replay')
async def replay_arc_dlq(request: Request, index: int = Body(..., embed=True)):
    _require_admin(request)
    _tenant_allow(request)
    rc = None
    try:
        rc = get_redis_client()
    except Exception:
        rc = None
    if rc is None:
        raise HTTPException(status_code=501, detail='redis not enabled')
    try:
        key = os.getenv('ARC_VERIFY_DLQ_KEY', 'arc:verify:dlq')
        # fetch item by index
        item = rc.lindex(key, index)
        if not item:
            raise HTTPException(status_code=404, detail='dlq index not found')
        p = json.loads(item)
        job = p.get('job') or {}
        # reset attempts and re-enqueue
        job['attempts'] = 0
        # encapsulate and push into delayed zset or immediate queue
        from src.core.arc_redis_queue import enqueue_job
        enqueue_job(job)
        # remove from DLQ
        rc.lrem(key, 1, item)
        # write audit entry (db-backed when available)
        try:
            entry = {'action':'replay_by_index','index':index,'req_id': job.get('req_id') if isinstance(job, dict) else None,'actor': request.headers.get('x-admin-key') or request.headers.get('x-api-key'),'ts': int(time.time())}
            try:
                from src.repositories.dlq_audit_repo import insert_audit
                import asyncio
                asyncio.run(insert_audit(entry))
            except Exception:
                # fallback to file append
                audit_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
                os.makedirs(audit_dir, exist_ok=True)
                audit_path = os.path.join(audit_dir, 'arc_dlq_replay_audit.jsonl')
                with open(audit_path, 'a', encoding='utf-8') as ah:
                    ah.write(json.dumps(entry) + '\n')
        except Exception:
            pass
        return {'ok': True}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@router.post('/api/v1/admin/arc/dlq/accelerate')
async def accelerate_delayed_item(request: Request, index: int = Body(..., embed=True)):
    """Move delayed zset item at `index` to immediate queue (or set next_run=now)."""
    _require_admin(request)
    _tenant_allow(request)
    rc = None
    try:
        rc = get_redis_client()
    except Exception:
        rc = None
    if rc is None:
        raise HTTPException(status_code=501, detail='redis not enabled')
    try:
        z = os.getenv('ARC_VERIFY_DELAYED_ZSET', 'arc:verify:delayed')
        items = rc.zrange(z, 0, -1)
        if index < 0 or index >= len(items):
            raise HTTPException(status_code=404, detail='delayed_index_not_found')
        member = items[index]
        # move to immediate queue
        try:
            from src.core.arc_redis_queue import get_redis_client as _g, QUEUE_KEY
            rc.lpush(os.getenv('ARC_VERIFY_QUEUE_KEY','arc:verify:queue'), member)
            rc.zrem(z, member)
            return {'ok': True}
        except Exception:
            # fallback: set score to now
            rc.zadd(z, {member: time.time()})
            return {'ok': True}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post('/api/v1/admin/arc/dlq/replay_bulk')
async def replay_bulk(request: Request, dry_run: bool = Body(True), max_items: int = Body(10)):
    """Bulk replay DLQ items. Dry-run returns how many would be replayed. Requires admin.

    This endpoint is rate-limited by tenant throttle and will re-enqueue up to `max_items`.
    """
    _require_admin(request)
    _tenant_allow(request)
    rc = None
    try:
        rc = get_redis_client()
    except Exception:
        rc = None
    if rc is None:
        raise HTTPException(status_code=501, detail='redis not enabled')
    try:
        key = os.getenv('ARC_VERIFY_DLQ_KEY', 'arc:verify:dlq')
        length = rc.llen(key)
        to_process = min(length, int(max_items))
        if dry_run:
            return {'dry_run': True, 'will_replay': to_process}
        # perform replay in small batches to avoid overload
        replayed = 0
        for i in range(to_process):
            item = rc.lindex(key, i)
            if not item:
                continue
            try:
                p = json.loads(item)
                job = p.get('job') or {}
                job['attempts'] = 0
                from src.core.arc_redis_queue import enqueue_job
                enqueue_job(job)
                rc.lrem(key, 1, item)
                # audit each
                try:
                    entry = {'action':'replay_bulk_item','req_id': job.get('req_id'),'actor': request.headers.get('x-admin-key') or request.headers.get('x-api-key'),'ts': int(time.time())}
                    try:
                        from src.repositories.dlq_audit_repo import insert_audit
                        import asyncio
                        asyncio.run(insert_audit(entry))
                    except Exception:
                        audit_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
                        os.makedirs(audit_dir, exist_ok=True)
                        audit_path = os.path.join(audit_dir, 'arc_dlq_replay_audit.jsonl')
                        with open(audit_path, 'a', encoding='utf-8') as ah:
                            ah.write(json.dumps(entry) + '\n')
                except Exception:
                    pass
                replayed += 1
            except Exception:
                continue
        return {'ok': True, 'replayed': replayed}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post('/api/v1/admin/arc/dlq/replay_by_req')
async def replay_arc_dlq_by_req(request: Request, req_id: str = Body(..., embed=True)):
    _require_admin(request)
    _tenant_allow(request)
    rc = None
    try:
        rc = get_redis_client()
    except Exception:
        rc = None
    if rc is None:
        raise HTTPException(status_code=501, detail='redis not enabled')
    key = os.getenv('ARC_VERIFY_DLQ_KEY', 'arc:verify:dlq')
    try:
        # scan DLQ for matching job with req_id
        length = rc.llen(key)
        for i in range(length):
            item = rc.lindex(key, i)
            if not item:
                continue
            try:
                p = json.loads(item)
                job = p.get('job') or {}
                if job.get('req_id') == req_id:
                    # reset attempts and re-enqueue
                    job['attempts'] = 0
                    from src.core.arc_redis_queue import enqueue_job
                    enqueue_job(job)
                    rc.lrem(key, 1, item)
                    # write audit via repo if available
                    try:
                        entry = {'action':'replay_by_req','req_id': req_id,'actor': request.headers.get('x-admin-key') or request.headers.get('x-api-key'),'ts': int(time.time())}
                        try:
                            from src.repositories.dlq_audit_repo import insert_audit
                            import asyncio
                            asyncio.run(insert_audit(entry))
                        except Exception:
                            audit_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))
                            os.makedirs(audit_dir, exist_ok=True)
                            audit_path = os.path.join(audit_dir, 'arc_dlq_replay_audit.jsonl')
                            with open(audit_path, 'a', encoding='utf-8') as ah:
                                ah.write(json.dumps(entry) + '\n')
                    except Exception:
                        pass
                    return {'ok': True, 'replayed': req_id}
            except Exception:
                continue
        raise HTTPException(status_code=404, detail='req_id not found in DLQ')
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


def _tenant_allow(req: Request):
    """Basic per-tenant throttle for admin actions.

    Uses Redis INCR with expiry when available. Falls back to an in-memory
    timestamp list. Controlled by ARC_ADMIN_THROTTLE_MAX and ARC_ADMIN_THROTTLE_WINDOW_SECONDS.
    """
    tenant = req.headers.get('X-Tenant-ID') or req.headers.get('x-tenant-id') or os.getenv('TENANT_ID') or 'default'
    max_ops = int(os.getenv('ARC_ADMIN_THROTTLE_MAX', '10'))
    window = int(os.getenv('ARC_ADMIN_THROTTLE_WINDOW_SECONDS', '60'))
    rc = None
    try:
        rc = get_redis_client()
    except Exception:
        rc = None
    if rc is not None:
        key = f"arc:admin:throttle:{tenant}"
        try:
            cnt = rc.incr(key)
            if cnt == 1:
                rc.expire(key, window)
            if cnt > max_ops:
                raise HTTPException(status_code=429, detail='tenant throttle exceeded')
            return True
        except HTTPException:
            raise
        except Exception:
            # fallback to in-memory below
            pass

    # In-memory fallback (best-effort, not persistent across processes)
    now = time.time()
    arr = _THROTTLE_STORE.get(tenant) or []
    # drop old entries
    arr = [t for t in arr if now - t < window]
    if len(arr) >= max_ops:
        raise HTTPException(status_code=429, detail='tenant throttle exceeded')
    arr.append(now)
    _THROTTLE_STORE[tenant] = arr
    return True


__all__ = ['router']
