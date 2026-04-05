from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime
from src.connectors.email.click_events import ClickEvent, ClickEventHandler
from src.connectors.email.click_persistence import enqueue_click

router = APIRouter(prefix="/api/v1/webhooks/email", tags=["email-webhooks"])


class ClickPayload(BaseModel):
    message_id: str
    user: str
    url: str
    timestamp: str
    verdict: str = "unknown"
    user_agent: str = None
    ip: str = None


@router.post('/click')
async def ingest_click(payload: ClickPayload):
    evt = ClickEvent(payload.message_id, payload.user, payload.url, datetime.fromisoformat(payload.timestamp), payload.verdict, payload.user_agent, payload.ip)
    # Enqueue for enrichment + correlation
    enqueue_click(evt)
    return {"status": "queued"}


@router.post('/proofpoint')
async def proofpoint_webhook(request: Request):
    # Generic handler scaffold for Proofpoint TAP/webhook
    try:
        body = await request.json()
    except Exception:
        body = {}
    print('PROOFPOINT_WEBHOOK', body)
    return {"status": "ok"}


@router.post('/mimecast')
async def mimecast_webhook(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    print('MIMECAST_WEBHOOK', body)
    return {"status": "ok"}
