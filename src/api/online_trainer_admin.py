from __future__ import annotations
from fastapi import APIRouter, Request, HTTPException, Depends
from typing import Dict, Any
import os

router = APIRouter(prefix='/api/v1/admin/online_trainer', tags=['admin','trainer'])


def _admin_dep():
    try:
        from src.security.auth import auth_dependency
    except Exception:
        # fallback: require ADMIN_API_KEY header
        def _fallback(request: Request):
            key = request.headers.get('x-admin-key') or request.headers.get('X-Admin-Key')
            expected = os.getenv('ADMIN_API_KEY') or os.getenv('API_KEY')
            if not expected or key != expected:
                raise HTTPException(status_code=403, detail='forbidden')
            return True
        return Depends(_fallback)
    def _dep(x_api_key: str | None = None, authorization: str | None = None):
        ctx = auth_dependency(x_api_key, authorization, ['models.promote'])
        try:
            import asyncio
            if asyncio.iscoroutine(ctx):
                ctx = asyncio.get_event_loop().run_until_complete(ctx)
        except Exception:
            pass
        try:
            if hasattr(ctx, 'has_role') and ctx.has_role('admin'):
                return ctx
        except Exception:
            pass
        return ctx
    return Depends(_dep)


@router.get('/candidates')
async def list_candidates(dep: Any = _admin_dep()):
    try:
        from src.ml.closed_loop_manager import ClosedLoopManager
        clm = ClosedLoopManager()
        # list_candidates is sync and fast; run in executor if necessary
        import asyncio
        loop = asyncio.get_event_loop()
        cands = await loop.run_in_executor(None, clm.list_candidates)
        return {'candidates': cands}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'list_failed:{exc}')


@router.get('/candidates/{candidate_id}/diff')
async def candidate_diff(candidate_id: int, dep: Any = _admin_dep()):
    try:
        from src.ml.closed_loop_manager import ClosedLoopManager
        from src.core.repositories import factor_weights_repo
        clm = ClosedLoopManager()
        cands = clm.list_candidates()
        cand = next((c for c in cands if int(c.get('id')) == int(candidate_id)), None)
        if not cand:
            raise KeyError('candidate_not_found')
        # load current weights
        try:
            current = factor_weights_repo.get_current_weights()  # may be async; best-effort
            import asyncio
            if hasattr(current, '__await__'):
                try:
                    current = asyncio.get_event_loop().run_until_complete(current)
                except Exception:
                    current = {}
        except Exception:
            current = {}
        # compute diff
        try:
            cand_weights = cand.get('candidate') or {}
            diffs = {}
            for k, v in (cand_weights.items() if isinstance(cand_weights, dict) else []):
                old = (current or {}).get(k)
                diffs[k] = {'old': old, 'new': v}
        except Exception:
            diffs = {'error': 'diff_failed'}
        return {'candidate_id': candidate_id, 'diff': diffs, 'summary': cand.get('summary')}
    except KeyError:
        raise HTTPException(status_code=404, detail='candidate_not_found')
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'diff_failed:{exc}')


@router.post('/candidates/{candidate_id}/approve')
async def approve_candidate(candidate_id: int, payload: Dict | None = None, dep: Any = _admin_dep()):
    actor = (payload or {}).get('actor') or 'admin'
    try:
        from src.ml.closed_loop_manager import ClosedLoopManager
        clm = ClosedLoopManager()
        current = (payload or {}).get('current_weights')
        applied = await clm.approve_candidate_async(candidate_id, actor, current_weights=current)
        return {'applied': applied}
    except KeyError:
        raise HTTPException(status_code=404, detail='candidate_not_found')
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f'approve_failed:{exc}')
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.ml.online_trainer import generate_candidate_weights, promote_candidates_to_prod

router = APIRouter(prefix='/api/v1/online_trainer', tags=['OnlineTrainer'])


class RunIn(BaseModel):
    window: str = '30 days'
    tenant_id: str | None = None
    max_delta: float = 0.05


@router.post('/run_now')
async def run_now(payload: RunIn):
    try:
        cand = await generate_candidate_weights(window=payload.window, tenant_id=payload.tenant_id, max_delta=payload.max_delta)
        return {'ok': True, 'candidates': cand}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


class PromoteIn(BaseModel):
    tenant_id: str | None = None
    candidates: dict | None = None


@router.post('/promote')
async def promote(payload: PromoteIn):
    try:
        if payload.candidates is None:
            # load latest snapshot from file
            import json, os
            path = 'data/factor_weight_snapshots.jsonl'
            if not os.path.exists(path):
                raise RuntimeError('no_snapshot')
            with open(path, 'r', encoding='utf-8') as fh:
                last = None
                for line in fh:
                    try:
                        last = json.loads(line)
                    except Exception:
                        continue
            if not last:
                raise RuntimeError('no_snapshot')
            candidates = last.get('candidates', {})
        else:
            candidates = payload.candidates
        await promote_candidates_to_prod(candidates, payload.tenant_id)
        return {'ok': True}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
