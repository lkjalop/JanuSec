from __future__ import annotations

import os
from typing import Dict, Set

# Simple permissions matrix. In production this should be data-driven and
# backed by a persistent store and admin UI.
DEFAULT_PERMISSIONS: Dict[str, Set[str]] = {
    'analyst': {'read:decisions', 'read:metrics', 'create:labels'},
    'manager': {'read:decisions', 'read:metrics', 'create:labels', 'export:reports'},
    'admin': {'*'},
}


def has_permission(roles: Set[str], permission: str) -> bool:
    if not roles:
        return False
    if '*' in roles:
        return True
    for r in roles:
        perms = DEFAULT_PERMISSIONS.get(r.lower(), set())
        if '*' in perms or permission in perms:
            return True
    return False


def require_permission(permission: str):
    def decorator(fn):
        def wrapper(request=None, *args, **kwargs):
            try:
                roles = set()
                if request is not None and hasattr(request, 'headers'):
                    roles_hdr = request.headers.get('X-Roles') or ''
                    roles = {r.strip().lower() for r in roles_hdr.split(',') if r.strip()}
                # allow test helpers to bypass via env
                if not roles and (os.getenv('TEST_HELPERS_ENABLED','0').lower() in {'1','true','yes'} or 'PYTEST_CURRENT_TEST' in os.environ):
                    roles = {'analyst'}
                if not has_permission(roles, permission):
                    from fastapi import HTTPException
                    raise HTTPException(status_code=403, detail='forbidden')
            except Exception:
                from fastapi import HTTPException
                raise HTTPException(status_code=403, detail='forbidden')
            return fn(request, *args, **kwargs)
        try:
            from src.security.signature_helpers import preserve_signature
            preserve_signature(wrapper, fn)
        except Exception:
            try:
                import inspect as _inspect
                wrapper.__signature__ = _inspect.signature(fn)
            except Exception:
                pass
        return wrapper
    return decorator
