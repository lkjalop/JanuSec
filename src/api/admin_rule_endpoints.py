from fastapi import APIRouter, Request, HTTPException, Depends
from typing import Dict, Any
from src.core.correlation.rules.rule_thresholds import to_dict, get_threshold, set_threshold, reset_to_env_defaults
from src.security.roles import require_roles

router = APIRouter(dependencies=[Depends(require_roles('admin'))])


def _admin_ok(request: Request) -> bool:
    key = request.headers.get('x-admin-key') or request.headers.get('X-Admin-Key')
    expected = __import__('os').getenv('ADMIN_API_KEY') or __import__('os').getenv('X_ADMIN_KEY')
    return bool(expected) and key == expected


@router.get('/api/v1/admin/rules')
async def get_rules(request: Request) -> Dict[str, Any]:
    if not _admin_ok(request):
        raise HTTPException(status_code=403, detail='forbidden')
    return to_dict()


@router.post('/api/v1/admin/rules')
async def set_rules(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    if not _admin_ok(request):
        raise HTTPException(status_code=403, detail='forbidden')
    # payload is a mapping of threshold_name->value
    for k, v in (payload or {}).items():
        try:
            set_threshold(k, v, persist=True)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f'invalid_{k}: {exc}')
    return to_dict()


@router.post('/api/v1/admin/rules/reset')
async def reset_rules(request: Request) -> Dict[str, Any]:
    if not _admin_ok(request):
        raise HTTPException(status_code=403, detail='forbidden')
    reset_to_env_defaults(persist=True)
    return to_dict()
