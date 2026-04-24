"""API routes for the decision lifecycle store.

Provides:
  GET  /api/v1/decisions/lifecycle/recent     — latest decisions (all states)
  GET  /api/v1/decisions/lifecycle/summary     — aggregate counts by state
  GET  /api/v1/decisions/lifecycle/{event_id}  — full audit trail for one event
  POST /api/v1/decisions/lifecycle/{event_id}/transition — state change
  POST /api/v1/decisions/lifecycle/{event_id}/correlation — isolated↔correlated
  GET  /api/v1/decisions/lifecycle/export       — full JSONL export (compliance)
"""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from src.api.decision_lifecycle import (
    DECISION_LIFECYCLE,
    VALID_CORRELATION_STATES,
    VALID_STATES,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix='/api/v1/decisions/lifecycle', tags=['decision-lifecycle'])


class TransitionRequest(BaseModel):
    new_state: str = Field(..., description='Target state')
    actor: str = Field(default='analyst', max_length=128)
    reason: str = Field(default='', max_length=4000)
    disposition: str = Field(default='')
    priority: str = Field(default='')
    factors: list[str] = Field(default_factory=list)
    triage_score: float = Field(default=0.0)
    correlation_state: str = Field(default='')
    escalation_plan: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)


class CorrelationChangeRequest(BaseModel):
    new_correlation: str = Field(..., description='isolated or correlated')
    actor: str = Field(default='system', max_length=128)
    reason: str = Field(default='', max_length=4000)


@router.get('/recent')
async def list_recent(
    state: str = Query(default='', description='Filter by state'),
    limit: int = Query(default=200, ge=1, le=1000),
):
    if state:
        if state not in VALID_STATES:
            raise HTTPException(400, f'invalid state: must be one of {sorted(VALID_STATES)}')
        return {'decisions': DECISION_LIFECYCLE.list_by_state(state, limit=limit)}
    return {'decisions': DECISION_LIFECYCLE.list_recent(limit=limit)}


@router.get('/summary')
async def summary_stats():
    return DECISION_LIFECYCLE.summary_stats()


@router.get('/export')
async def export_full_log():
    """Full append-only JSONL export for compliance/audit."""
    records = DECISION_LIFECYCLE.all_records()
    return {
        'format': 'jsonl_inline',
        'record_count': len(records),
        'records': records,
        'exported_at': time.time(),
        'note': 'Each record is a single state transition. Records are append-only and never mutated.',
    }


@router.get('/{event_id}')
async def get_event_lifecycle(event_id: str):
    history = DECISION_LIFECYCLE.get_history(event_id)
    current = DECISION_LIFECYCLE.get_current(event_id)
    if not current:
        raise HTTPException(404, 'event_not_found')
    return {
        'event_id': event_id,
        'current': current,
        'history': history,
        'transition_count': len(history),
    }


@router.post('/{event_id}/transition')
async def transition_state(event_id: str, payload: TransitionRequest):
    if payload.new_state not in VALID_STATES:
        raise HTTPException(400, f'invalid_state: must be one of {sorted(VALID_STATES)}')
    if payload.correlation_state and payload.correlation_state not in VALID_CORRELATION_STATES:
        raise HTTPException(400, f'invalid_correlation_state: must be one of {sorted(VALID_CORRELATION_STATES)}')

    rec = DECISION_LIFECYCLE.transition(
        event_id=event_id,
        new_state=payload.new_state,
        actor=payload.actor,
        reason=payload.reason,
        disposition=payload.disposition,
        priority=payload.priority,
        factors=payload.factors,
        triage_score=payload.triage_score,
        correlation_state=payload.correlation_state,
        escalation_plan=payload.escalation_plan,
        metadata=payload.metadata,
    )
    return {'status': 'transitioned', 'record': rec}


@router.post('/{event_id}/correlation')
async def change_correlation(event_id: str, payload: CorrelationChangeRequest):
    if payload.new_correlation not in VALID_CORRELATION_STATES:
        raise HTTPException(400, f'invalid_correlation: must be one of {sorted(VALID_CORRELATION_STATES)}')
    current = DECISION_LIFECYCLE.get_current(event_id)
    if not current:
        raise HTTPException(404, 'event_not_found — transition to a state first')
    rec = DECISION_LIFECYCLE.change_correlation(
        event_id=event_id,
        new_correlation=payload.new_correlation,
        actor=payload.actor,
        reason=payload.reason,
    )
    return {'status': 'correlation_changed', 'record': rec}
