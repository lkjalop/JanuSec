"""Minimal RBAC scaffolding with lightweight disk persistence.

Features:
 - In-memory role map keyed by api_key (string) -> set[str] roles.
 - JSON persistence to `data/roles.json` (location override via ROLE_STORE_PATH env).
 - Helper functions: assign_role, revoke_role, list_roles, has_role.
 - Decorator `require_role` raising PermissionError when role missing.

Future work: integrate with API key / token subsystem & tenant isolation.
This module intentionally avoids heavy dependencies to keep startup cost low.
"""
from __future__ import annotations
from functools import wraps
from typing import Callable, Any, Dict, Set
import os, json, threading, time

_ROLE_STORE_PATH = os.getenv('ROLE_STORE_PATH') or os.path.join('data', 'roles.json')
_ROLE_MAP: Dict[str, Set[str]] = {}
_LOCK = threading.RLock()

def _ensure_dir(path: str):
    try:
        d = os.path.dirname(path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
    except Exception:
        pass

def _persist():
    """Persist current role map to disk (best-effort)."""
    with _LOCK:
        try:
            _ensure_dir(_ROLE_STORE_PATH)
            data = {k: sorted(list(v)) for k, v in _ROLE_MAP.items()}
            tmp = _ROLE_STORE_PATH + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump({'roles': data, 'ts': time.time()}, fh)
            os.replace(tmp, _ROLE_STORE_PATH)
        except Exception:
            pass

def _load_existing():
    with _LOCK:
        try:
            if not os.path.exists(_ROLE_STORE_PATH):
                return
            with open(_ROLE_STORE_PATH, 'r', encoding='utf-8') as fh:
                doc = json.load(fh)
            raw = (doc or {}).get('roles') or {}
            for k, roles in raw.items():
                if isinstance(roles, list):
                    _ROLE_MAP[k] = set(r for r in roles if isinstance(r, str))
        except Exception:
            pass

_load_existing()

def assign_role(api_key: str, role: str):
    with _LOCK:
        _ROLE_MAP.setdefault(api_key, set()).add(role)
    _persist()

def revoke_role(api_key: str, role: str):
    with _LOCK:
        try:
            roles = _ROLE_MAP.get(api_key)
            if roles and role in roles:
                roles.remove(role)
        except Exception:
            pass
    _persist()

def list_roles(api_key: str) -> set[str]:
    return set(_ROLE_MAP.get(api_key, set()))

def has_role(api_key: str, role: str) -> bool:
    return role in _ROLE_MAP.get(api_key, set())

def require_role(role: str):
    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*a, **kw):
            # Expect api_key either as kwarg or in first arg context object
            api_key = kw.get('api_key') or kw.get('apikey')
            if api_key is None and a:
                # heuristic: context object with attribute api_key
                ctx = a[0]
                api_key = getattr(ctx, 'api_key', None)
            if api_key is None or role not in _ROLE_MAP.get(api_key, set()):
                raise PermissionError(f'missing required role: {role}')
            return fn(*a, **kw)
        # Preserve original signature to avoid frameworks (FastAPI) creating
        # spurious query parameters when wrappers expose **kwargs. Use a
        # centralized helper so preservation happens immediately at decoration
        # time and is robust across import/registration ordering.
        try:
            from .signature_helpers import preserve_signature
            preserve_signature(wrapper, fn)
        except Exception:
            try:
                import inspect as _inspect
                wrapper.__signature__ = _inspect.signature(fn)
            except Exception:
                pass
        return wrapper
    return decorator

__all__ = ['assign_role','revoke_role','list_roles','has_role','require_role']
