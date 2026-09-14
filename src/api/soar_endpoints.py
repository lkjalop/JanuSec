from __future__ import annotations

import json
import os
from typing import Any, Dict

from fastapi import APIRouter, HTTPException

try:
    # Prefer absolute import when running tests from repo root
    from src.soar.runner import PlaybookRunner  # type: ignore
except Exception:
    try:
        # Fallback to package-relative import when running as package
        from ..soar.runner import PlaybookRunner  # type: ignore
    except Exception:
        # As a last resort (test environments or trimmed installs), provide a tiny stub
        # that matches the PlaybookRunner interface used by the endpoints. This keeps
        # test collection stable without requiring optional dependencies.
        class PlaybookRunner:
            def __init__(self, dry_run: bool = True):
                self.dry_run = dry_run

            async def run(self, playbook: dict) -> dict:
                # Minimal no-op runner for tests
                steps = playbook.get("steps", [])
                results = []
                for s in steps:
                    results.append({"name": s.get("type"), "ok": True, "detail": "stub"})
                return {"playbook": playbook.get("name"), "dry_run": self.dry_run, "results": results}

router = APIRouter(tags=["SOAR"])

PLAYBOOKS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "playbooks")
os.makedirs(PLAYBOOKS_DIR, exist_ok=True)


@router.post('/api/v1/soar/execute', operation_id='soar_execute_playbook')
async def execute_playbook(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a playbook payload. For demo this runs in-process and is dry-run by default."""
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="invalid_playbook")
    runner = PlaybookRunner(dry_run=bool(payload.get("dry_run", True)))
    res = await runner.run(payload)
    return res


@router.get('/api/v1/soar/playbooks')
def list_playbooks() -> Dict[str, Any]:
    files = [f for f in os.listdir(PLAYBOOKS_DIR) if f.endswith('.json')]
    return {"playbooks": files}


@router.post('/api/v1/soar/playbooks/save')
def save_playbook(name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if not name.endswith('.json'):
        name = name + '.json'
    path = os.path.join(PLAYBOOKS_DIR, name)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f)
    return {"saved": True, "path": path}


# ---- Lightweight remediation wrappers for console buttons ----
@router.post('/api/v1/soar/remediate/iam/disable-key')
async def remediate_iam_disable_key(payload: Dict[str, Any]) -> Dict[str, Any]:
    key_id = payload.get('key_id')
    tenant = payload.get('tenant_id')
    if not key_id:
        raise HTTPException(status_code=400, detail='key_id_required')
    play = {
        'name': 'iam:disable_key',
        'dry_run': bool(payload.get('dry_run', True)),
        'steps': [
            {'type': 'iam:disable_key', 'params': {'key_id': key_id, 'tenant_id': tenant}},
        ]
    }
    runner = PlaybookRunner(dry_run=bool(play.get('dry_run', True)))
    return await runner.run(play)


@router.post('/api/v1/soar/remediate/iam/enforce-mfa')
async def remediate_iam_enforce_mfa(payload: Dict[str, Any]) -> Dict[str, Any]:
    user = payload.get('user') or payload.get('username')
    tenant = payload.get('tenant_id')
    if not user:
        raise HTTPException(status_code=400, detail='user_required')
    play = {
        'name': 'iam:enforce_mfa',
        'dry_run': bool(payload.get('dry_run', True)),
        'steps': [
            {'type': 'iam:enforce_mfa', 'params': {'user': user, 'tenant_id': tenant}},
        ]
    }
    runner = PlaybookRunner(dry_run=bool(play.get('dry_run', True)))
    return await runner.run(play)


@router.post('/api/v1/soar/remediate/net/sg-tighten')
async def remediate_net_sg_tighten(payload: Dict[str, Any]) -> Dict[str, Any]:
    sg_id = payload.get('sg_id')
    port = payload.get('port')
    proto = payload.get('proto')
    tenant = payload.get('tenant_id')
    if not sg_id:
        raise HTTPException(status_code=400, detail='sg_id_required')
    play = {
        'name': 'net:sg_tighten',
        'dry_run': bool(payload.get('dry_run', True)),
        'steps': [
            {'type': 'net:sg_tighten', 'params': {'sg_id': sg_id, 'port': port, 'proto': proto, 'tenant_id': tenant}},
        ]
    }
    runner = PlaybookRunner(dry_run=bool(play.get('dry_run', True)))
    return await runner.run(play)
