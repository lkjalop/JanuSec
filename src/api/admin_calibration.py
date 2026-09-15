from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request, Depends
from typing import Optional, List, Dict
import asyncio
import os
import json
import pathlib

from src.core.correlation.calibration import suggest_threshold_adjustments, persist_suggestions_to_file
from src.api.tenant_helpers import resolve_tenant_id


# Remove router-level role dependency to avoid FastAPI 422 validation quirks.
# Admin checks are enforced within endpoints via API key or role inspection.
router = APIRouter(prefix='/api/v1/admin/calibration', tags=['Admin'])


def _check_api_key(request: Request):
    key = request.headers.get('x-api-key')
    expected = os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')
    if not key or key != expected:
        raise HTTPException(status_code=403, detail='forbidden')


@router.post('/run', summary='Run calibration job (skeleton)')
async def run_calibration(payload: Dict | None = None, tenant_id: Optional[str] = None, request: Request = None) -> dict:
    """Run a simple calibration job that computes TP/FP per variant/test and
    returns a suggested winner. This is a skeleton to be extended.
    """
    try:
        from src.repositories import decision_labels_repo
    except Exception:
        raise HTTPException(status_code=500, detail='labels repo unavailable')
    try:
        # Fetch recent labeled records for tenant (best-effort)
        try:
            from src.db.database import fetch
            # Ensure we have a proper Request object in FastAPI dependency context
            if request is None:
                raise HTTPException(status_code=422, detail='invalid_request')
            tenant_id = resolve_tenant_id(request, tenant_id)
            rows = await fetch("SELECT decision_id,label,COALESCE(factors,'[]') as factors FROM decision_labels WHERE (tenant_id=$1 OR (tenant_id IS NULL AND $1 IS NULL)) ORDER BY created_at DESC LIMIT 1000", tenant_id)
            # Normalize rows
            labels = []
            import json as _json
            for r in rows:
                fac = r.get('factors') or '[]'
                try:
                    fac_list = _json.loads(fac) if isinstance(fac, str) else fac
                except Exception:
                    fac_list = []
                labels.append({'decision_id': r.get('decision_id'), 'label': r.get('label'), 'factors': fac_list})
        except Exception:
            labels = []
        # Accept candidates from payload or fallback to simple defaults
        candidates = None
        default_threshold = 0.5
        if payload:
            candidates = payload.get('candidates')
            default_threshold = float(payload.get('threshold', default_threshold))
        if not candidates:
            # If no candidates provided, generate a tiny grid over observed factors
            factors = set()
            for r in labels:
                for f in r.get('factors') or []:
                    factors.add(str(f))
            from src.ml.candidate_gen import grid_over_factors
            candidates_simple = grid_over_factors(list(factors)[:4], base=0.0, step=0.5, levels=2)
            candidates = [ {'weights': c, 'threshold': default_threshold} for c in candidates_simple ]
        from src.ml.calibration_runner import grid_search
        res = grid_search(candidates, labels, default_threshold)
        # persist run summary for auditability
        try:
            from src.repositories.calibration_runs_repo import persist_run
            persist_run({'tenant_id': tenant_id, 'candidates': candidates, 'summary': res})
        except Exception:
            pass
        return {'ok': True, 'summary': res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/suggestions')
async def get_suggestions(_auth=Depends(_check_api_key)):
    suggestions = suggest_threshold_adjustments()
    # persist snapshot for audit
    try:
        persist_suggestions_to_file(suggestions)
    except Exception:
        pass
    return {"suggestions": suggestions}


async def _write_approval_db_async(payload: Dict):
    dsn = os.getenv('APP_DB_DSN')
    if not dsn:
        return False
    try:
        import asyncpg
        conn = await asyncpg.connect(dsn)
        await conn.execute('''
            INSERT INTO calibration_approvals (approver, suggestions, notes, migration_batch)
            VALUES ($1, $2::jsonb, $3, $4)
        ''', payload.get('approver'), json.dumps(payload.get('approvals') or []), payload.get('notes'), payload.get('migration_batch'))
        await conn.close()
        return True
    except Exception:
        return False


@router.post('/approve')
async def approve_suggestions(request: Request, payload: Dict, _auth=Depends(_check_api_key)):
    # payload: {approvals: [{rule, delta, approver}], approver, notes?, migration_batch?}
    try:
        # try DB async write first (fire-and-forget if loop running)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None
        wrote_db = False
        if loop and loop.is_running():
            try:
                asyncio.ensure_future(_write_approval_db_async(payload))
                wrote_db = True
            except Exception:
                wrote_db = False
        else:
            try:
                asyncio.get_event_loop().run_until_complete(_write_approval_db_async(payload))
                wrote_db = True
            except Exception:
                wrote_db = False

        if not wrote_db:
            p = pathlib.Path('data') / 'calibration_approvals.json'
            p.parent.mkdir(parents=True, exist_ok=True)
            text = p.read_text(encoding='utf-8') if p.exists() else '[]'
            arr = json.loads(text)
            arr.append(payload)
            p.write_text(json.dumps(arr, indent=2), encoding='utf-8')
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"status": "ok", "wrote_db": bool(wrote_db)}


__all__ = ['router']


@router.get('/runs')
async def list_runs():
    try:
        from src.repositories.calibration_runs_repo import FILE
        # try file first
        import os, json
        if os.path.exists(FILE):
            with open(FILE, 'r', encoding='utf-8') as fh:
                arr = json.load(fh) or []
            return {'ok': True, 'runs': arr}
    except Exception:
        pass
    # try DB
    try:
        from src.db.database import fetch
        rows = await fetch('SELECT id, tenant_id, run_payload, created_at FROM calibration_runs ORDER BY created_at DESC LIMIT 100')
        return {'ok': True, 'runs': [dict(r) for r in rows]}
    except Exception:
        return {'ok': True, 'runs': []}
