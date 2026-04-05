from fastapi import APIRouter, HTTPException
import os
import json
import time
from typing import Dict, Any

router = APIRouter()

PERSIST_DIR = os.environ.get('SESSION_PERSIST_DIR', os.path.join('data', 'backfill'))
os.makedirs(PERSIST_DIR, exist_ok=True)


def _persist_state(assessment_id: str, state: Dict[str, Any]):
    path = os.path.join(PERSIST_DIR, f"{assessment_id}.json")
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(state, f)


def _load_state(assessment_id: str) -> Dict[str, Any]:
    path = os.path.join(PERSIST_DIR, f"{assessment_id}.json")
    if not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


@router.post('/api/v1/csv/deep_analyze/auto_backfill')
def start_auto_backfill(payload: Dict[str, Any]):
    assessment_id = payload.get('assessment_id') or payload.get('id')
    if not assessment_id:
        raise HTTPException(status_code=400, detail='missing assessment_id')
    state = _load_state(assessment_id)
    if state.get('state') == 'running':
        return {'ok': True, 'started': False, 'reason': 'already running'}
    state.update({
        'assessment_id': assessment_id,
        'state': 'running',
        'progress': {'processed': 0, 'total': payload.get('total_rows') or 0},
        'started_at': time.time()
    })
    _persist_state(assessment_id, state)
    return {'ok': True, 'started': True, 'assessment_id': assessment_id}


@router.get('/api/v1/csv/deep_analyze/auto_backfill/{assessment_id}/status')
def get_backfill_status(assessment_id: str):
    state = _load_state(assessment_id)
    if not state:
        raise HTTPException(status_code=404, detail='not found')
    return state


@router.post('/api/v1/csv/deep_analyze/auto_backfill/{assessment_id}/stop')
def stop_backfill(assessment_id: str):
    state = _load_state(assessment_id)
    if not state:
        raise HTTPException(status_code=404, detail='not found')
    state['state'] = 'stopped'
    state['stopped_at'] = time.time()
    _persist_state(assessment_id, state)
    return {'ok': True, 'stopped': True}
