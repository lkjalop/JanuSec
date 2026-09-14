"""Automation hook endpoints (placeholder for future SOAR integration)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, Depends

from security.auth import require_scopes

LOG_PATH = Path('data/automation_requests.jsonl')

router = APIRouter(prefix='/api/v1/automations', tags=['Automations'])


def _append(entry: Dict[str, Any]) -> None:
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(entry) + '\n')
    except Exception:
        pass


@router.post('/run', summary='Trigger an automation playbook (placeholder)')  # type: ignore[misc]
async def run_automation(payload: Dict[str, Any], request: Request, auth: object = Depends(require_scopes('feedback.write'))) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail='invalid_payload')
    entry = {
        'ts': time.time(),
        'playbook_id': payload.get('playbook_id'),
        'parameters': payload.get('parameters') or {},
        'requested_by': payload.get('requested_by') or (request.client.host if request.client else None),
        'status': 'queued',
    }
    _append(entry)
    return {'status': 'queued', 'playbook_id': entry['playbook_id']}


@router.get('/requests', summary='List automation requests')  # type: ignore[misc]
async def list_automation_requests(limit: int = 200) -> Dict[str, Any]:
    if not LOG_PATH.exists():
        return {'requests': []}
    rows = []
    try:
        with LOG_PATH.open('r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        rows = []
    return {'requests': rows[-limit:]}
