from __future__ import annotations

import time
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix='/api/v1/integrations/eclipse', tags=['Integrations'])


@router.post('/ingest')
async def eclipse_ingest(request: Request) -> Dict[str, Any]:
    """Receive Eclipse.XDR alert payloads and publish decision summaries for classification/enrichment."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='bad_json')
    # Normalize a minimal decision summary
    alert = payload.get('alert') or payload
    event_id = str(alert.get('id') or f"ecl-{int(time.time()*1000)}")
    title = alert.get('title') or alert.get('name') or 'eclipse_alert'
    try:
        from .decisions_stream import publish_decision
        summary = {
            'event_id': event_id,
            'title': title,
            'verdict': 'OBSERVE',
            'confidence': 0.0,
            'factors': ['eclipse:ingest'],
            'integrator_id': 'eclipse',
            'ts': time.time(),
        }
        await publish_decision(summary)
    except Exception:
        pass
    return {'accepted': True, 'event_id': event_id}


@router.post('/writeback')
async def eclipse_writeback(alert_id: str, add_tags: list[str] | None = None, severity: str | None = None, note: str | None = None) -> Dict[str, Any]:
    from integrations.eclipse_adapter import CLIENT
    res = await CLIENT.update_alert(alert_id, add_tags=add_tags, severity=severity, note=note)
    return {'alert_id': alert_id, **res}

__all__ = ['router']
