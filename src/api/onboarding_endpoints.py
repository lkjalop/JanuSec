from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import List, Dict
import os, json
from src.api.tenant_helpers import resolve_tenant_id

router = APIRouter(prefix="/api/v1/onboarding", tags=["onboarding"])

MAPPINGS_DIR = os.getenv('MAPPINGS_DIR','data/mappings')
TENANT_DIR = os.getenv('TENANT_DATA_DIR','data/tenants')
os.makedirs(TENANT_DIR, exist_ok=True)

class ConnectorConfig(BaseModel):
    connector_type: str
    connector_category: str
    connector_name: str
    config: Dict = {}

class OnboardingRequest(BaseModel):
    tenant_id: str
    connectors: List[ConnectorConfig]


def _tenant_connectors_path(tenant_id: str) -> str:
    safe = tenant_id.replace('..','').replace('/','_')
    d = os.path.join(TENANT_DIR, safe)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, 'connectors.json')


@router.post('/configure')
async def configure_tenant(request: OnboardingRequest, http_request: Request):
    tenant_id = resolve_tenant_id(http_request, request.tenant_id) or request.tenant_id
    path = _tenant_connectors_path(tenant_id)
    rows = [c.dict() for c in request.connectors]
    try:
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(rows, fh, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    # For now: return basic summary. Playbook generation and escalation wiring
    # will be performed by background tasks in future steps.
    return {
        'status': 'success',
        'tenant_id': tenant_id,
        'connectors_configured': len(rows),
        'playbooks_generated': 0,
        'features_enabled': ['missing_log_detection','llm_personalization']
    }
