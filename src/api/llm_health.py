from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from src.integrations import llm_client
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


class PrewarmRequest(BaseModel):
    model: Optional[str] = None
    num_predict: Optional[int] = 8


@router.get('/api/v1/llm/health')
def llm_health():
    client = llm_client.DEFAULT_CLIENT
    provider = getattr(client, 'provider', 'unknown')
    mock = getattr(client, 'mock', False)
    local_det = provider == 'local-deterministic'
    return {
        'provider': provider,
        'requested_provider': provider,
        'environment': 'mock' if mock else ('local' if local_det else 'remote'),
        'available': True,
        'strict_provider': False,
        'fallback_active': local_det,
        'fallback_reason': 'local-deterministic fallback active' if local_det else None,
        'local_deterministic_active': local_det,
        'ollama_enabled': getattr(client, 'ollama_enabled', False),
        'ollama_host': getattr(client, 'ollama_host', None),
        'ollama_model': getattr(client, 'ollama_model', None),
        'ollama_reachable': getattr(client, 'ollama_reachable', False),
        'mock': mock,
    }


@router.post('/api/v1/llm/prewarm')
def llm_prewarm(req: PrewarmRequest):
    client = llm_client.DEFAULT_CLIENT
    model = req.model or getattr(client, 'ollama_model', None)
    try:
        # best-effort prewarm: small generate to warm model
        overrides = {}
        if getattr(client, 'ollama_enabled', False):
            overrides = {'ollama_model': model}
        resp = client.generate('prewarm: warm the model', max_tokens=req.num_predict or 8, overrides=overrides)
        return {'ok': True, 'response_preview': str(resp)[:400]}
    except Exception as e:
        logger.exception('Prewarm failed: %s', e)
        raise HTTPException(status_code=500, detail=str(e))
