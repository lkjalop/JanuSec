from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
import hashlib
import random

from src.repositories.ab_test_repo import assign_variant, get_test
from .tenant_helpers import resolve_tenant_id

router = APIRouter()


class AssignIn(BaseModel):
    test_id: str
    tenant_id: Optional[str]
    subject_id: str
    rollout_pct: Optional[int] = None  # override


@router.post('/api/v1/ab_test/assign')
async def assign(incoming: AssignIn, request: Request = None):
    """Deterministic assignment: hash(subject_id + test_id) -> variant A/B by rollout_pct."""
    t = await get_test(incoming.test_id)
    if not t:
        raise HTTPException(status_code=404, detail='test not found')

    # determine rollout
    pct = incoming.rollout_pct if incoming.rollout_pct is not None else int(t.get('rollout_pct', 50))
    # deterministic hash
    h = hashlib.sha256((incoming.subject_id + incoming.test_id).encode('utf-8')).digest()
    v = int.from_bytes(h[:2], 'big') % 100
    variant = 'B' if v < pct else 'A'

    try:
        incoming.tenant_id = resolve_tenant_id(request, incoming.tenant_id)
    except Exception:
        pass
    # persist assignment for visibility
    await assign_variant(incoming.test_id, incoming.tenant_id, incoming.subject_id, variant)
    return {'ok': True, 'variant': variant}
