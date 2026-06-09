from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Depends

from src.artifact.memory_repository import MEMORY_JOB_STORE, record_memory_job, MemoryJobStore
from src.integrations.sandbox.cuckoo_provider import CuckooProvider
from src.security.crypto_utils import encrypt_secret, decrypt_secret
from src.security.roles import get_request_roles

router = APIRouter()
LOG = logging.getLogger(__name__)


async def _admin_dep(request: Request) -> None:
    """FastAPI-compatible dependency: raises 403 if caller does not have admin role."""
    roles = get_request_roles(request)
    if 'admin' not in roles:
        raise HTTPException(status_code=403, detail='forbidden_role')


class IntegrationsConfigPayload(dict):
    pass


@router.post('/api/v1/integrations/{name}/config')
async def set_integration_config(name: str, request: Request, auth=Depends(_admin_dep)):
    """Accepts a JSON payload and stores it in a local file under data/integrations/{name}.json for demo/admin use."""
    try:
        payload = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f'invalid json: {exc}')

    path = f'data/integrations/{name}.json'
    try:
        import os
        os.makedirs('data/integrations', exist_ok=True)
        # encrypt api_key if present
        if 'api_key' in payload and payload.get('api_key'):
            try:
                payload['api_key'] = encrypt_secret(payload['api_key'])
                payload['_api_key_encrypted'] = True
            except Exception:
                LOG.exception('failed to encrypt api_key; saving plaintext')
                payload['_api_key_encrypted'] = False

        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh)
    except Exception as exc:
        LOG.exception('failed to persist integration config')
        raise HTTPException(status_code=500, detail=str(exc))

    return {'status': 'ok', 'path': path}


@router.get('/api/v1/admin/sandbox/tasks')
async def list_sandbox_tasks(limit: int = 50, auth=Depends(_admin_dep)):
    """List recent memory jobs with sandbox submissions (reads from MEMORY_JOB_STORE)."""
    try:
        store = MemoryJobStore()
        jobs = store.recent(limit=limit)
        # filter jobs that have sandbox keys
        has = [j for j in jobs if j.get('sandbox') or j.get('task_id') or (j.get('sandbox', {}) and j.get('sandbox').get('task_id'))]
        return {'count': len(has), 'tasks': has}
    except Exception as exc:
        LOG.exception('failed to list sandbox tasks')
        raise HTTPException(status_code=500, detail=str(exc))


@router.post('/api/v1/admin/sandbox/refresh')
async def refresh_sandbox_task(task_id: str, auth=Depends(_admin_dep)):
    """Force-refresh a sandbox task by calling the provider's result() and persisting the result."""
    store = MemoryJobStore()
    job = store.recent(limit=200)
    # find job by job_id
    found = None
    for j in job:
        if j.get('job_id') == task_id or j.get('task_id') == task_id:
            found = j
            break

    if not found:
        # fallback: try get by direct lookup
        found = store.record_job({'job_id': task_id})

    provider_name = (found.get('provider') or found.get('sandbox', {}).get('provider') or 'cuckoo')
    provider = None
    if provider_name == 'cuckoo':
        provider = CuckooProvider()
    else:
        try:
            from src.integrations.sandbox.generic_provider import GenericSandboxProvider

            provider = GenericSandboxProvider(provider_name)
        except Exception:
            provider = CuckooProvider()

    async def _fetch_and_record(tid: str):
        try:
            res = await provider.result(tid)
            record_memory_job({
                'job_id': tid,
                'provider': provider_name,
                'sandbox': {'status': 'refreshed', 'verdict': (res or {}).get('verdict') if isinstance(res, dict) else None, 'submitted_at': None},
                'result': res,
            })
        finally:
            try:
                await provider.close()
            except Exception:
                pass

    asyncio.create_task(_fetch_and_record(task_id))
    return {'status': 'refresh_scheduled', 'task_id': task_id, 'provider': provider_name}
