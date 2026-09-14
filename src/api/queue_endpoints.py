"""Operator Queue API endpoints.

Mounted at /api/v1/queue  (included by app.py).

Routes
──────
GET  /api/v1/queue/{assessment_id}
    Return the full queue view (active/remainder/escalated/deferred/cleared)
    for the given assessment, optionally filtered by persona.

POST /api/v1/queue/{assessment_id}/build
    (Re)build the queue from the current assessment state.
    Replaces any previously built queue for this assessment.
    Body: {persona?: str}

POST /api/v1/queue/{assessment_id}/action
    Apply an analyst or system action to a specific queue item.
    Body: {item_id, action, actor?, evidence_refs?, rationale?,
           reopen_at?, reopen_conditions?}

POST /api/v1/queue/{assessment_id}/evidence
    Push new rows into an existing queue, running corroboration delta
    and TTL re-evaluation.
    Body: {rows: [...]}

GET  /api/v1/queue/{assessment_id}/item/{item_id}
    Return a single queue item by ID including its full action history.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/api/v1/queue', tags=['operator_queue'])

# ── Queue storage ─────────────────────────────────────────────────────────────
# Assessment-local: one queue list per assessment_id.
# In-memory for close-beta; an optional JSON-disk persist runs asynchronously.
# The queue is rebuilt from the assessment on demand — no separate DB needed.

_QUEUE_STORE: dict[str, list[dict[str, Any]]] = {}  # assessment_id -> [QueueItem]


def _get_queue(assessment_id: str) -> list[dict[str, Any]]:
    return _QUEUE_STORE.get(assessment_id, [])


def _save_queue(assessment_id: str, items: list[dict[str, Any]]) -> None:
    _QUEUE_STORE[assessment_id] = items
    _persist_queue_async(assessment_id, items)


def _persist_queue_async(assessment_id: str, items: list[dict[str, Any]]) -> None:
    """Non-blocking disk persist.  Failures are logged but never surfaced."""
    try:
        from src.api.persist_utils import atomic_write_json
        queue_dir = os.path.join('data', 'queues')
        os.makedirs(queue_dir, exist_ok=True)
        path = os.path.join(queue_dir, f'queue_{assessment_id}.json')
        atomic_write_json(path, {'assessment_id': assessment_id, 'items': items, 'updated_at': time.time()})
    except Exception as exc:
        logger.debug('queue persist skipped: %s', exc)


def _load_persisted_queue(assessment_id: str) -> list[dict[str, Any]] | None:
    try:
        import json
        path = os.path.join('data', 'queues', f'queue_{assessment_id}.json')
        if not os.path.exists(path):
            return None
        with open(path) as f:
            data = json.load(f)
        items = data.get('items') or []
        _QUEUE_STORE[assessment_id] = items
        return items
    except Exception:
        return None


def _resolve_queue(assessment_id: str) -> list[dict[str, Any]] | None:
    items = _QUEUE_STORE.get(assessment_id)
    if items is not None:
        return items
    return _load_persisted_queue(assessment_id)


def _get_assessment(assessment_id: str) -> dict[str, Any] | None:
    try:
        from src.api.deep_analyze_endpoints import _get_assessment_cached
        return _get_assessment_cached(assessment_id)
    except Exception:
        return None


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get('/{assessment_id}')
async def get_queue(
    assessment_id: str,
    persona: str = 'soc_analyst',
    request: Request = None,
) -> JSONResponse:
    """Return the operator queue view for an assessment."""
    from src.core.operator_queue.queue_model import get_queue_view, reopen_expired_deferred

    items = _resolve_queue(assessment_id)
    if not items:
        # Auto-build on first read if the assessment exists
        assessment = _get_assessment(assessment_id)
        if not assessment:
            raise HTTPException(status_code=404, detail='assessment_not_found')
        from src.core.operator_queue.queue_model import build_queue_from_assessment
        items = build_queue_from_assessment(assessment, persona=persona)
        _save_queue(assessment_id, items)

    # Always run TTL re-evaluation before returning
    from src.core.operator_queue.queue_model import reopen_expired_deferred
    items = reopen_expired_deferred(items)
    _QUEUE_STORE[assessment_id] = items  # update in-memory with any transitions

    view = get_queue_view(items)
    return JSONResponse({'status': 'ok', 'assessment_id': assessment_id, 'queue': view})


@router.post('/{assessment_id}/build')
async def build_queue(
    assessment_id: str,
    request: Request = None,
) -> JSONResponse:
    """(Re)build the operator queue from the current assessment state."""
    from src.core.operator_queue.queue_model import build_queue_from_assessment, get_queue_view

    body: dict = {}
    try:
        body = await request.json()
    except Exception:
        pass

    persona = str(body.get('persona') or 'soc_analyst')
    assessment = _get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail='assessment_not_found')

    items = build_queue_from_assessment(assessment, persona=persona)
    _save_queue(assessment_id, items)
    view = get_queue_view(items)

    return JSONResponse({
        'status': 'ok',
        'assessment_id': assessment_id,
        'persona': persona,
        'queue': view,
    })


@router.post('/{assessment_id}/action')
async def queue_action(
    assessment_id: str,
    request: Request = None,
) -> JSONResponse:
    """Apply an analyst action to a QueueItem.

    Body:
      item_id       str   (required)
      action        str   confirm|deny|defer|escalate|reopen|add_evidence
      actor         str   (default: analyst)
      evidence_refs list  (optional row refs like ['R12', 'R34'])
      rationale     str   (optional free text — stored in action record)
      reopen_at     float (epoch; required for defer action)
      reopen_conditions list[str] (optional conditions for defer)
    """
    from src.core.operator_queue.queue_model import apply_action, QueueAction, get_queue_view, reopen_expired_deferred

    body: dict = {}
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')

    item_id = str(body.get('item_id') or '')
    action_str = str(body.get('action') or '')
    if not item_id or not action_str:
        raise HTTPException(status_code=400, detail='item_id_and_action_required')

    try:
        action = QueueAction(action_str)
    except ValueError:
        raise HTTPException(status_code=400, detail=f'unknown_action: {action_str}')

    items = _resolve_queue(assessment_id)
    if items is None:
        raise HTTPException(status_code=404, detail='queue_not_found')

    item = next((it for it in items if it['item_id'] == item_id), None)
    if not item:
        raise HTTPException(status_code=404, detail='item_not_found')

    reopen_at_raw = body.get('reopen_at')
    reopen_at = float(reopen_at_raw) if reopen_at_raw else None
    reopen_conditions = body.get('reopen_conditions') or []

    updated = apply_action(
        item,
        action,
        actor=str(body.get('actor') or 'analyst'),
        evidence_refs=body.get('evidence_refs') or [],
        rationale=str(body.get('rationale') or ''),
        reopen_at=reopen_at,
        reopen_conditions=reopen_conditions,
    )

    _save_queue(assessment_id, items)
    items = reopen_expired_deferred(items)

    view = get_queue_view(items)
    return JSONResponse({
        'status': 'ok',
        'assessment_id': assessment_id,
        'item_id': item_id,
        'new_state': updated.get('state'),
        'queue_counts': view['counts'],
    })


@router.post('/{assessment_id}/evidence')
async def push_evidence(
    assessment_id: str,
    request: Request = None,
) -> JSONResponse:
    """Push new rows into the queue for corroboration delta + TTL re-evaluation.

    This is how Approach A (corroboration) and Approach C (TTL) are triggered:
    new telemetry rows arrive → entity overlap detection → auto-promotion of
    Deferred/Remainder items that now have more evidence.

    Body: {rows: [... row dicts ...]}
    """
    from src.core.operator_queue.queue_model import (
        apply_new_evidence, reopen_expired_deferred, get_queue_view,
    )

    body: dict = {}
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_json')

    new_rows = body.get('rows') or []
    if not new_rows:
        raise HTTPException(status_code=400, detail='rows_required')

    items = _resolve_queue(assessment_id)
    if items is None:
        raise HTTPException(status_code=404, detail='queue_not_found')

    items = reopen_expired_deferred(items)
    items = apply_new_evidence(items, new_rows)
    _save_queue(assessment_id, items)

    view = get_queue_view(items)

    # Count how many items received corroboration
    corroborated = sum(
        1 for it in items
        if any(a.get('action') == 'corroborate' for a in (it.get('actions') or []))
    )

    return JSONResponse({
        'status': 'ok',
        'assessment_id': assessment_id,
        'rows_processed': len(new_rows),
        'items_corroborated': corroborated,
        'queue_counts': view['counts'],
    })


@router.get('/{assessment_id}/item/{item_id}')
async def get_item(
    assessment_id: str,
    item_id: str,
    request: Request = None,
) -> JSONResponse:
    """Return a single queue item with its full audit trail."""
    items = _resolve_queue(assessment_id)
    if items is None:
        raise HTTPException(status_code=404, detail='queue_not_found')

    item = next((it for it in items if it['item_id'] == item_id), None)
    if not item:
        raise HTTPException(status_code=404, detail='item_not_found')

    return JSONResponse({'status': 'ok', 'item': item})
