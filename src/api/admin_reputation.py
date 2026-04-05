from fastapi import APIRouter, HTTPException, Depends
from typing import Any
from src.security.roles import require_roles

router = APIRouter(prefix='/admin/asn_reputation', dependencies=[Depends(require_roles('admin'))])


@router.post('/reload')
def reload_reputation() -> Any:
    try:
        from src.core.enrichment.asn_reputation import load_reputation
        res = load_reputation()
        return {'status': 'ok', 'loaded': len(res)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
