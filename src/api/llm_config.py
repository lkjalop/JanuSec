from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from typing import Optional
from ..core.config import llm_settings_store as store
from ..integrations.llm_client import LLMClient

router = APIRouter()


class LLMConfigIn(BaseModel):
    provider: Optional[str] = None
    ollama_host: Optional[str] = None
    ollama_model: Optional[str] = None
    ollama_generate_path: Optional[str] = None


@router.get('/api/v1/config/llm')
def get_llm_config():
    settings = store.load_settings() or {}
    client = LLMClient()
    health = client.health()
    return {'settings': settings, 'health': health}


@router.post('/api/v1/config/llm')
async def post_llm_config(req: Request, payload: LLMConfigIn):
    api_key = req.headers.get('x-api-key')
    if not api_key or api_key != req.app.state.api_key:
        raise HTTPException(status_code=403, detail='forbidden')

    new = {k: v for k, v in payload.dict().items() if v is not None}
    # validate by creating a client with overrides and probing
    client = LLMClient(overrides=new)
    health = client.health()
    if health.get('ollama', {}).get('enabled') and not health.get('ollama', {}).get('reachable'):
        raise HTTPException(status_code=400, detail='ollama unreachable with provided host')

    settings = store.load_settings() or {}
    settings.update(new)
    store.save_settings(settings)
    return {'ok': True, 'settings': settings, 'health': health}
