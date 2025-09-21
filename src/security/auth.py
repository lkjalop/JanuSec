"""Lightweight auth layer supporting either static API keys with scopes or JWT tokens.

Usage:
- Configure environment variables:
  API_KEYS_JSON='[{"key":"abc123","scopes":["nlp.query","factors.search","feedback.write"]}]'
  JWT_SECRET='supersecret'
  JWT_AUDIENCE='threat-sifter'
  JWT_ISSUER='your-company'

For JWT, payload must include 'scopes' claim (list of scope strings) or a role that maps to scopes.
"""
from __future__ import annotations
import os, json, time
from typing import List, Dict, Any, Optional
from fastapi import Header, HTTPException, Depends

try:
    import jwt  # pyjwt
except Exception:  # pragma: no cover
    jwt = None  # type: ignore

class AuthContext:
    def __init__(self, subject: str, scopes: List[str]):
        self.subject = subject
        self.scopes = scopes

_API_KEYS: Dict[str, List[str]] | None = None
_ROLE_MAP: Dict[str, List[str]] = {
    'analyst': ['nlp.query','factors.search','feedback.write'],
    'viewer': ['nlp.query','factors.search'],
    'admin': ['*']
}

def _load_api_keys():
    global _API_KEYS
    if _API_KEYS is not None:
        return _API_KEYS
    raw = os.getenv('API_KEYS_JSON','')
    data: Dict[str, List[str]] = {}
    if raw:
        try:
            arr = json.loads(raw)
            for entry in arr:
                k = entry.get('key')
                sc = entry.get('scopes', [])
                if k:
                    data[k] = sc
        except Exception:
            pass
    _API_KEYS = data
    return data

def _jwt_secret():
    return os.getenv('JWT_SECRET')

def _match_scopes(user_scopes: List[str], required: List[str]) -> bool:
    if any(s == '*' for s in user_scopes):
        return True
    for rs in required:
        if rs not in user_scopes:
            return False
    return True

async def auth_dependency(x_api_key: Optional[str] = Header(None), authorization: Optional[str] = Header(None), required_scopes: Optional[List[str]] = None) -> AuthContext:
    required_scopes = required_scopes or []
    # 1. API Key path
    api_keys = _load_api_keys()
    if x_api_key and x_api_key in api_keys:
        scopes = api_keys[x_api_key]
        if not _match_scopes(scopes, required_scopes):
            raise HTTPException(status_code=403, detail='insufficient_scope')
        return AuthContext(subject=f'api_key:{x_api_key[:4]}', scopes=scopes)
    # 2. JWT path
    if authorization and authorization.startswith('Bearer '):
        if not _jwt_secret() or jwt is None:
            raise HTTPException(status_code=401, detail='jwt_not_supported')
        token = authorization.split(' ',1)[1]
        try:
            payload = jwt.decode(token, _jwt_secret(), algorithms=['HS256'], audience=os.getenv('JWT_AUDIENCE'), issuer=os.getenv('JWT_ISSUER'))
        except Exception:
            raise HTTPException(status_code=401, detail='invalid_token')
        scopes: List[str] = payload.get('scopes') or []
        role = payload.get('role')
        if role and not scopes:
            scopes = _ROLE_MAP.get(role, [])
        if not _match_scopes(scopes, required_scopes):
            raise HTTPException(status_code=403, detail='insufficient_scope')
        return AuthContext(subject=payload.get('sub','unknown'), scopes=scopes)
    raise HTTPException(status_code=401, detail='unauthorized')

# Convenience wrappers for FastAPI dependencies
from functools import partial

def require_scopes(*scopes: str):
    async def _dep(x_api_key: Optional[str] = Header(None), authorization: Optional[str] = Header(None)):
        return await auth_dependency(x_api_key, authorization, list(scopes))
    return _dep
