from fastapi import APIRouter, Header, HTTPException, Body
from typing import Any, Dict, Optional
import time

router = APIRouter(prefix="/api/v1/connectivity", tags=["connectivity-smoke"])


@router.post('/smoke')
async def smoke(
    payload: Dict[str, Any] = Body(...),
    api_key: Optional[str] = Header(None, alias='x-api-key'),
):
    if not api_key:
        raise HTTPException(status_code=401, detail='missing_api_key')
    return {
        'ok': True,
        'received': payload,
        'ts': time.time(),
        'note': 'Connectivity smoke ok: payload echoed back',
    }
