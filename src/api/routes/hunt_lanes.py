from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from db.database import DatabaseNotAvailable, get_pool
from src.repositories.hunt_lane_events_repo import HuntLaneEventsRepository

router = APIRouter()


async def _get_repository() -> HuntLaneEventsRepository:
    try:
        pool = await get_pool()
    except DatabaseNotAvailable:
        pool = None
    return HuntLaneEventsRepository(pool)


@router.get('/api/v1/hunt/lanes/events')
async def list_hunt_lane_events(
    lane: Optional[str] = Query(None, description='Optional lane filter'),
    limit: int = Query(100, ge=1, le=500),
    tenant_id: Optional[str] = Header(default=None, alias='X-Tenant-ID'),
    repo: HuntLaneEventsRepository = Depends(_get_repository),
) -> dict:
    if repo.require_tenant and not tenant_id:
        raise HTTPException(status_code=422, detail='tenant_required')
    try:
        events = await repo.recent(tenant_id, lane=lane, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        'tenant_id': tenant_id,
        'lane': lane,
        'limit': limit,
        'events': events,
    }


__all__ = ['router']
