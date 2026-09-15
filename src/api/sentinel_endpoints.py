"""API endpoints for the Azure Sentinel workspace connector.

Routes::

    GET  /api/v1/sentinel/incidents
    GET  /api/v1/sentinel/incidents/{id}
    POST /api/v1/sentinel/incidents/{id}/status
    GET  /api/v1/sentinel/incidents/{id}/alerts
    GET  /api/v1/sentinel/watchlists
    GET  /api/v1/sentinel/watchlists/{alias}/items
    POST /api/v1/sentinel/query          — KQL query
    GET  /api/v1/sentinel/ping           — connectivity check
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/sentinel', tags=['Sentinel'])


def _connector():
    from src.connectors.azure.sentinel_workspace import get_sentinel_connector
    return get_sentinel_connector()


# ── Request models ────────────────────────────────────────────────────

class IncidentStatusUpdate(BaseModel):
    status: str                         # New | Active | Closed
    classification: Optional[str] = None
    owner_email: Optional[str] = None


class KQLRequest(BaseModel):
    kql: str
    timespan: Optional[str] = 'P1D'


# ── Incidents ─────────────────────────────────────────────────────────

@router.get('/incidents')
async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    top: int = 50,
) -> Dict[str, Any]:
    try:
        items = _connector().list_incidents(
            status_filter=status, severity_filter=severity, top=top
        )
        return {'incidents': items, 'count': len(items)}
    except Exception as exc:
        logger.error('Sentinel list_incidents error: %s', exc)
        raise HTTPException(status_code=502, detail=f'sentinel_api_error: {exc}')


@router.get('/incidents/{incident_id}')
async def get_incident(incident_id: str) -> Dict[str, Any]:
    try:
        return _connector().get_incident(incident_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.post('/incidents/{incident_id}/status')
async def update_incident_status(
    incident_id: str,
    body: IncidentStatusUpdate,
) -> Dict[str, Any]:
    valid = {'New', 'Active', 'Closed'}
    if body.status not in valid:
        raise HTTPException(status_code=400, detail=f'status must be one of {valid}')
    try:
        return _connector().update_incident_status(
            incident_id=incident_id,
            status=body.status,
            classification=body.classification,
            owner_email=body.owner_email,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.get('/incidents/{incident_id}/alerts')
async def incident_alerts(incident_id: str) -> Dict[str, Any]:
    try:
        alerts = _connector().list_incident_alerts(incident_id)
        return {'alerts': alerts, 'count': len(alerts)}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


# ── Watchlists ────────────────────────────────────────────────────────

@router.get('/watchlists')
async def list_watchlists() -> Dict[str, Any]:
    try:
        items = _connector().list_watchlists()
        return {'watchlists': items, 'count': len(items)}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@router.get('/watchlists/{alias}/items')
async def watchlist_items(alias: str, limit: int = 500) -> Dict[str, Any]:
    try:
        items = _connector().get_watchlist_items(alias, limit=limit)
        return {'items': items, 'count': len(items)}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


# ── KQL query ─────────────────────────────────────────────────────────

@router.post('/query')
async def kql_query(body: KQLRequest) -> Dict[str, Any]:
    if not body.kql.strip():
        raise HTTPException(status_code=400, detail='empty_kql')
    try:
        rows = _connector().query(kql=body.kql, timespan=body.timespan)
        return {'rows': rows, 'count': len(rows)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))


# ── Healthcheck ───────────────────────────────────────────────────────

@router.get('/ping')
async def sentinel_ping() -> Dict[str, Any]:
    return _connector().ping()
