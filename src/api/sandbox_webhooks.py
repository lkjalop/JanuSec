from __future__ import annotations

import hmac
import hashlib
import json
import logging
from fastapi import APIRouter, Request, HTTPException

from src.artifact.memory_repository import record_memory_job

router = APIRouter()
LOG = logging.getLogger(__name__)


def _verify_hmac(secret: str, body: bytes, header_val: str) -> bool:
    try:
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, header_val)
    except Exception:
        return False


@router.post('/api/v1/sandbox/webhook/{provider_name}')
async def sandbox_webhook(provider_name: str, request: Request):
    body = await request.body()
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail='invalid json')

    # Load provider config to find webhook secret
    cfg_path = f'data/integrations/{provider_name}.json'
    secret = None
    try:
        with open(cfg_path, 'r', encoding='utf-8') as fh:
            cfg = json.load(fh)
            secret = cfg.get('webhook_secret')
            header_name = cfg.get('webhook_secret_header', 'X-Sandbox-Signature')
    except Exception:
        header_name = 'X-Sandbox-Signature'

    header_val = request.headers.get(header_name)
    if secret:
        if not header_val or not _verify_hmac(secret, body, header_val):
            LOG.warning('webhook signature failed for provider %s', provider_name)
            raise HTTPException(status_code=403, detail='invalid signature')

    # Normalize payload minimally and record into memory job store
    try:
        task_id = payload.get('task_id') or payload.get('id') or payload.get('uuid')
        job = {
            'job_id': task_id or payload.get('report_id') or None,
            'sandbox': {'status': 'webhook', 'verdict': payload.get('verdict') or payload.get('status'), 'submitted_at': payload.get('submitted_at')},
            'result': payload,
        }
        record_memory_job(job)
    except Exception as exc:
        LOG.exception('failed to persist webhook payload')
        raise HTTPException(status_code=500, detail=str(exc))

    return {'status': 'ok'}
