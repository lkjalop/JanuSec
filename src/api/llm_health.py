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
    status = llm_client.get_client_status(client)
    return {
        'provider': status.get('provider'),
        'requested_provider': status.get('requested_provider'),
        'environment': status.get('environment'),
        'available': status.get('available'),
        'strict_provider': status.get('strict_provider'),
        'fallback_active': status.get('fallback_active'),
        'fallback_reason': status.get('fallback_reason'),
        'local_deterministic_active': status.get('local_deterministic_active'),
        'ollama_enabled': status.get('ollama_enabled', getattr(client, 'ollama_enabled', False)),
        'ollama_host': status.get('ollama_host', getattr(client, 'ollama_host', None)),
        'ollama_model': status.get('ollama_model', getattr(client, 'ollama_model', None)),
        'ollama_reachable': status.get('ollama_reachable', False),
        'mock': getattr(client, 'mock', False),
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
