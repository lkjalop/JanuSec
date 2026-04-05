from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from src.core.ab.shadow_runner import enable_test, disable_test, is_enabled
from src.repositories.ab_test_repo import upsert_test, get_test, list_all

router = APIRouter(prefix='/api/v1/ab_test', tags=['ABTest'])


class EnableIn(BaseModel):
    test_id: str
    name: Optional[str]
    rollout_pct: int = 10


@router.post('/enable')
async def enable(incoming: EnableIn):
    # try to persist test record; if DB disabled, continue with in-memory enable
    try:
        await upsert_test(incoming.test_id, incoming.name or incoming.test_id, 'auto-enabled', True, None, None)
    except Exception:
        # DB not available in test mode; proceed without persistence
        pass
    enable_test(incoming.test_id, incoming.rollout_pct)
    return {'ok': True, 'test_id': incoming.test_id, 'rollout_pct': incoming.rollout_pct}


class DisableIn(BaseModel):
    test_id: str


@router.post('/disable')
async def disable(incoming: DisableIn):
    disable_test(incoming.test_id)
    return {'ok': True}


@router.get('/list')
async def list_tests():
    tests = await list_all()
    return {'ok': True, 'tests': tests}
