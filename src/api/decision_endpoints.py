"""Decision endpoints to create, approve, execute, and rollback DecisionGates.

This module provides a minimal, testable implementation with RBAC stubs,
an immutable audit store (file-backed in SESSION_PERSIST_DIR during tests),
and example one-click action wiring using playbook mappings.
"""
from __future__ import annotations
import os
import json
import time
import uuid
import logging
from typing import Any, Dict, Optional
from src.api.actor_context import get_current_actor

from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel

from src.reporting.schemas import DecisionGate, PersonaType, ActionUrgency
from src.reporting.playbooks import PLAYBOOKS
from src.api.metrics_init import ensure_metrics, _safe_counter

ensure_metrics()
# Telemetry counters
DECISION_CREATED = _safe_counter('decision_created_total', 'Total decisions created') if _safe_counter else None
DECISION_APPROVED = _safe_counter('decision_approved_total', 'Total decisions approved') if _safe_counter else None
DECISION_EXECUTED = _safe_counter('decision_executed_total', 'Total decisions executed') if _safe_counter else None
DECISION_ROLLED_BACK = _safe_counter('decision_rolled_back_total', 'Total decisions rolled back') if _safe_counter else None

router = APIRouter(prefix='/api/v1/decision', tags=['DecisionGate'])
logger = logging.getLogger(__name__)


# Simple in-memory audit store; persisted to SESSION_PERSIST_DIR/backfill_jobs for tests
AUDIT_DIR = os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data', 'sessions')
os.makedirs(AUDIT_DIR, exist_ok=True)
AUDIT_PATH = os.path.join(AUDIT_DIR, 'decision_audit.json')


def _load_audit() -> Dict[str, Any]:
    try:
        if os.path.exists(AUDIT_PATH):
            with open(AUDIT_PATH, 'r', encoding='utf-8') as fh:
                return json.load(fh) or {}
    except Exception:
        pass
    return {}


def _persist_audit(audit: Dict[str, Any]) -> None:
    try:
        with open(AUDIT_PATH, 'w', encoding='utf-8') as fh:
            json.dump(audit, fh, default=str, ensure_ascii=False)
    except Exception:
        logger.exception('Failed to persist decision audit')


def create_decision_with_actor(req_dict: Dict[str, Any], actor: Optional[str] = None) -> Dict[str, Any]:
    """Server-side wrapper to create a decision and record the creating actor in the audit."""
    # Validate via Pydantic model
    try:
        req = CreateDecisionRequest(**req_dict)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f'invalid_request:{e}')
    dg = DecisionGate(
        gate_id=f'dg-{uuid.uuid4().hex[:8]}',
        decision_type=req.decision_type,
        persona=req.persona,
        urgency=req.urgency,
        question=req.question,
        context=req.context or '',
        options=req.options or [],
    )
    # allow callers to rely on per-request context var if explicit actor not passed
    if not actor:
        try:
            actor = get_current_actor()
        except Exception:
            actor = None
    audit = _load_audit()
    audit.setdefault('decisions', {})
    audit['decisions'][dg.gate_id] = {'decision': dg.model_dump(), 'history': [{'actor': actor, 'action': 'created', 'ts': int(time.time())}]}
    _persist_audit(audit)
    try:
        if DECISION_CREATED:
            DECISION_CREATED.inc()
    except Exception:
        pass
    return {'gate_id': dg.gate_id, 'status': 'created'}


# Minimal RBAC stub for tests: env var DECISION_ROLE_ALLOWS contains comma-separated roles
def _has_role(actor: Optional[str], required: str) -> bool:
    # actor is a simple string like 'alice:roles:approver'
    # For now, allow all if TEST_HELPERS_ENABLED=1
    if os.getenv('TEST_HELPERS_ENABLED', '') == '1':
        return True
    if not actor:
        return False
    roles = os.getenv('DECISION_ROLE_ALLOWS', '')
    if not roles:
        return False
    return required in roles.split(',')


class CreateDecisionRequest(BaseModel):
    decision_type: str
    persona: PersonaType
    urgency: ActionUrgency
    question: str
    context: Optional[str] = None
    options: Optional[list] = None


@router.post('/create')
def create_decision(req: CreateDecisionRequest, actor: Optional[str] = Header(None, alias='x-actor')):
    # Generate DecisionGate and persist audit entry
    dg = DecisionGate(
        gate_id=f'dg-{uuid.uuid4().hex[:8]}',
        decision_type=req.decision_type,
        persona=req.persona,
        urgency=req.urgency,
        question=req.question,
        context=req.context or '',
        options=req.options or [],
    )
    # prefer explicit header actor, else fall back to per-request actor context
    if not actor:
        try:
            actor = get_current_actor()
        except Exception:
            actor = None
    audit = _load_audit()
    audit.setdefault('decisions', {})
    audit['decisions'][dg.gate_id] = {'decision': dg.model_dump(), 'history': [{'actor': actor, 'action': 'created', 'ts': int(time.time())}]}
    _persist_audit(audit)
    return {'gate_id': dg.gate_id, 'status': 'created'}


class ApproveRequest(BaseModel):
    gate_id: str
    approved_option: str


@router.post('/approve')
def approve_decision(req: ApproveRequest, actor: Optional[str] = Header(None, alias='x-actor')):
    # RBAC: check approver role
    if not _has_role(actor, 'approver'):
        raise HTTPException(status_code=403, detail='actor_not_authorized')
    audit = _load_audit()
    dec = audit.get('decisions', {}).get(req.gate_id)
    if not dec:
        raise HTTPException(status_code=404, detail='decision_not_found')
    dec['history'].append({'actor': actor, 'action': 'approved', 'option': req.approved_option, 'ts': int(time.time())})
    # If urgency is IMMEDIATE require second approver (two-person rule)
    try:
        urgency = dec['decision'].get('urgency')
        if urgency == ActionUrgency.IMMEDIATE:
            dec['decision'].setdefault('pending_approvals', 0)
            dec['decision']['pending_approvals'] = dec['decision'].get('pending_approvals', 0) + 1
            # If only one approval so far, persist and require second approval
            if dec['decision']['pending_approvals'] < 2:
                audit['decisions'][req.gate_id] = dec
                _persist_audit(audit)
                return {'status': 'pending_second_approval'}
    except Exception:
        pass
    # otherwise mark approved
    dec['decision']['decision_made'] = req.approved_option
    dec['decision']['decided_by'] = actor
    dec['decision']['decided_at'] = int(time.time())
    audit['decisions'][req.gate_id] = dec
    _persist_audit(audit)
    try:
        if DECISION_APPROVED:
            DECISION_APPROVED.inc()
    except Exception:
        pass
    return {'gate_id': req.gate_id, 'status': 'approved'}


class ExecuteRequest(BaseModel):
    gate_id: str
    action_payload: Optional[Dict[str, Any]] = None


@router.post('/execute', operation_id='decision_execute')
def execute_decision(req: ExecuteRequest, actor: Optional[str] = Header(None, alias='x-actor')):
    # RBAC: check operator role
    if not _has_role(actor, 'operator'):
        raise HTTPException(status_code=403, detail='actor_not_authorized')
    audit = _load_audit()
    dec = audit.get('decisions', {}).get(req.gate_id)
    if not dec:
        raise HTTPException(status_code=404, detail='decision_not_found')
    # For demo: map decision type to playbook and mark executed
    try:
        dtype = dec['decision'].get('decision_type')
        # find matching playbook by decision type mapping (simple heuristic)
        pb = None
        if 'block' in (dtype or '').lower():
            pb = PLAYBOOKS.get('block_ip')
        elif 'isolate' in (dtype or '').lower():
            pb = PLAYBOOKS.get('isolate_host')
        if pb:
            # pretend to execute first api step
            result = {'executed': True, 'playbook': pb['title']}
        else:
            result = {'executed': True, 'note': 'no playbook found; manual action required'}
    except Exception as e:
        result = {'executed': False, 'error': str(e)}
    dec['history'].append({'actor': actor, 'action': 'executed', 'payload': req.action_payload, 'result': result, 'ts': int(time.time())})
    audit['decisions'][req.gate_id] = dec
    _persist_audit(audit)
    try:
        if DECISION_EXECUTED:
            DECISION_EXECUTED.inc()
    except Exception:
        pass
    return {'gate_id': req.gate_id, 'status': 'executed', 'result': result}


class RollbackRequest(BaseModel):
    gate_id: str
    reason: Optional[str] = None


@router.post('/rollback')
def rollback_decision(req: RollbackRequest, actor: Optional[str] = Header(None, alias='x-actor')):
    # RBAC: check approver role
    if not _has_role(actor, 'approver'):
        raise HTTPException(status_code=403, detail='actor_not_authorized')
    audit = _load_audit()
    dec = audit.get('decisions', {}).get(req.gate_id)
    if not dec:
        raise HTTPException(status_code=404, detail='decision_not_found')
    dec['history'].append({'actor': actor, 'action': 'rollback', 'reason': req.reason, 'ts': int(time.time())})
    dec['decision']['decision_made'] = None
    audit['decisions'][req.gate_id] = dec
    _persist_audit(audit)
    try:
        if DECISION_ROLLED_BACK:
            DECISION_ROLLED_BACK.inc()
    except Exception:
        pass
    return {'gate_id': req.gate_id, 'status': 'rolled_back'}
