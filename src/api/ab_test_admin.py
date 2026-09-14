from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from src.security.roles import require_roles

router = APIRouter(prefix='/api/v1/abtests', tags=['AB Tests'], dependencies=[Depends(require_roles('admin'))])


class ABTestCreate(BaseModel):
    id: str
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = False
    start_at: Optional[datetime] = None
    end_at: Optional[datetime] = None


class AssignPayload(BaseModel):
    test_id: str
    subject_id: str
    variant: str


@router.post('/create')
async def create_test(payload: ABTestCreate):
    try:
        from src.repositories import ab_test_repo
        await ab_test_repo.upsert_test(payload.id, payload.name, payload.description, bool(payload.enabled), payload.start_at.isoformat() if payload.start_at else None, payload.end_at.isoformat() if payload.end_at else None)
        return {'status': 'ok', 'test_id': payload.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post('/assign')
async def assign_variant(payload: AssignPayload, request: Request):
    try:
        tenant = getattr(request.state, 'tenant_id', None) or request.headers.get('X-Tenant-ID')
        from src.repositories import ab_test_repo
        await ab_test_repo.assign_variant(payload.test_id, tenant, payload.subject_id, payload.variant)
        return {'status': 'ok'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
