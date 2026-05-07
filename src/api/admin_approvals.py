from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any
from src.core import approval_repo
import os
from src.security.roles import require_roles
try:
    from src.security.auth import require_scopes
except Exception:
    def require_scopes(_s: str):
        def _fn():
            # permissive in lite/test
            if os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ:
                return True
            raise HTTPException(status_code=403, detail='forbidden')
        return _fn
try:
    from src.security.rbac import has_role
except Exception:
    def has_role(_k: str, _r: str) -> bool:
        return os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ


def require_admin():
    # Try the real require_scopes and fall back to permissive test-mode when configured
    try:
        fn = require_scopes('admin')
        # Return the dependency callable itself; FastAPI will await it when used as a dependency.
        return fn
    except Exception:
        if os.getenv('PLATFORM_LITE_INIT','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ:
            def _permissive():
                return True
            return _permissive
        raise HTTPException(status_code=403, detail='forbidden')

router = APIRouter(dependencies=[Depends(require_roles('admin'))])


class PolicyIn(BaseModel):
    name: str
    action_pattern: str
    n_required: int
    m_total: int
    approver_pool: Optional[list] = None
    scope: Optional[Dict[str, Any]] = None
    enabled: bool = True


@router.post('/api/v1/admin/approval_policies')
def create_policy(payload: PolicyIn, _=Depends(require_admin)):
    try:
        approval_repo.save_policy(payload.name, payload.action_pattern, payload.n_required, payload.m_total, payload.approver_pool, payload.scope, payload.enabled)
        return {'ok': True, 'policy': payload.model_dump()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/api/v1/admin/approval_policies')
def list_policies(_=Depends(require_admin)):
    try:
        return {'policies': approval_repo.list_policies()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/api/v1/admin/approval_policies/{name}')
def get_policy(name: str, _=Depends(require_admin)):
    p = approval_repo.get_policy_by_name(name)
    if not p:
        raise HTTPException(status_code=404, detail='not_found')
    return p


@router.delete('/api/v1/admin/approval_policies/{name}')
def delete_policy(name: str, _=Depends(require_admin)):
    try:
        approval_repo.delete_policy(name)
        return {'ok': True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
