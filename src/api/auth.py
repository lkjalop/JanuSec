from __future__ import annotations

import os
import time
import json
from typing import Optional
from fastapi import Request, HTTPException
from .session import verify_session_cookie


def _get_env(name: str) -> Optional[str]:
    v = os.getenv(name)
    return v if v and v.strip() else None


def _validate_admin_token(provided: Optional[str]) -> bool:
    token = _get_env('ADMIN_UI_TOKEN')
    if not token:
        return False
    return bool(provided and provided == token)


async def _validate_oidc_token(token: str) -> dict | None:
    """Lazily validate an OIDC id_token using the issuer's JWKS.

    Uses `core.jwks.get_jwks` to fetch a cached JWKS. Requires optional
    dependencies (`httpx` and `python-jose`) to be installed when OIDC is used.
    """
    issuer = _get_env('OIDC_ISSUER')
    client_id = _get_env('OIDC_CLIENT_ID')
    if not issuer or not client_id:
        return None
    try:
        from core.jwks import get_jwks
        jwks = get_jwks(issuer)
        if not jwks:
            return None
        try:
            from jose import jwt
        except Exception:
            # optional dep missing
            return None
        try:
            claims = jwt.decode(token, jwks, audience=client_id, issuer=issuer)
            # Optional JTI replay guard
            try:
                _enforce = os.getenv('OIDC_JTI_ENFORCE','0').lower() in {'1','true','yes'}
            except Exception:
                _enforce = False
            if _enforce:
                jti = claims.get('jti') or claims.get('nonce')
                exp = claims.get('exp')
                if jti:
                    if _jti_seen(jti):
                        return None
                    _jti_store(jti, exp)
            return claims
        except Exception:
            return None
    except Exception:
        return None

# In-memory JTI cache (best-effort) with TTL based on exp
_JTI_SEEN: dict[str, float] = {}

def _jti_seen(jti: str) -> bool:
    now = time.time()
    # prune
    for k, v in list(_JTI_SEEN.items()):
        if v and v < now:
            _JTI_SEEN.pop(k, None)
    return jti in _JTI_SEEN

def _jti_store(jti: str, exp: Optional[int]) -> None:
    try:
        ttl = float(exp) if exp else (time.time() + 600)
    except Exception:
        ttl = time.time() + 600
    _JTI_SEEN[jti] = ttl


async def check_admin_token_async(request: 'Request') -> None:
    """Async admin access check. Prefer this in async request handlers to
    properly await OIDC token validation and avoid coroutine warnings in test
    runners and async contexts.

    Behavior mirrors `check_admin_token`.
    """
    # Temporary testing bypass: if PLATFORM_LITE_INIT is enabled we allow
    # admin access for faster unit tests. Alternatively, an explicit
    # ADMIN_API_KEY env var can be set and the client may send
    # X-Admin-API-Key header matching it to authenticate.
    try:
        # Admin endpoints should ONLY bypass when ADMIN_PERMISSIVE_TEST=1 or test helpers explicitly enabled.
        admin_permissive = os.getenv('ADMIN_PERMISSIVE_TEST','0').lower() in {'1','true','yes'}
        test_helpers = os.getenv('TEST_HELPERS_ENABLED','0').lower() in {'1','true','yes'}
        _lite = admin_permissive or test_helpers
    except Exception:
        _lite = False
    admin_api_key = _get_env('ADMIN_API_KEY')
    admin_ui_token = _get_env('ADMIN_UI_TOKEN')
    if _lite and not admin_api_key and not admin_ui_token:
        request.state.user = {'sub': 'admin-lite', 'role': 'admin'}
        return
    if admin_api_key:
        provided_key = request.headers.get('X-Admin-API-Key') or request.headers.get('x-admin-api-key')
        if provided_key and provided_key == admin_api_key:
            request.state.user = {'sub': 'admin-api-key', 'role': 'admin'}
            return

    auth = request.headers.get('Authorization') or ''
    if auth.startswith('Bearer '):
        provided = auth.split(' ', 1)[1].strip()
        claims = await _validate_oidc_token(provided)
        if claims:
            try:
                request.state.user = {'sub': claims.get('sub'), 'email': claims.get('email')}
            except Exception:
                request.state.user = {'sub': claims.get('sub')}
            return
    # token header fallback
    provided_token = None
    if auth.startswith('Bearer '):
        provided_token = auth.split(' ', 1)[1].strip()
    else:
        provided_token = request.headers.get('X-Admin-Token') or request.headers.get('x-admin-token')
    if _validate_admin_token(provided_token):
        request.state.user = {'sub': 'admin-token', 'role': 'admin'}
        return
    raise HTTPException(status_code=401, detail='unauthorized')


def _verify_session_cookie(cookie_val: str) -> dict | None:
    # delegate to session manager
    try:
        return verify_session_cookie(cookie_val)
    except Exception:
        return None


def check_admin_token(request: Request) -> None:
    """Enforce admin access.

    Behavior:
    - If OIDC_ISSUER and OIDC_CLIENT_ID are set, expect a valid Bearer ID token
      (Authorization header) or a session cookie created after OIDC login.
    - Otherwise require ADMIN_UI_TOKEN to be set and matched via header.
    - Deny-by-default when neither SSO nor ADMIN_UI_TOKEN is configured.
    """
    # Temporary testing bypass: accept when PLATFORM_LITE_INIT is set or
    # when ADMIN_API_KEY matches X-Admin-API-Key header.
    try:
        admin_permissive = os.getenv('ADMIN_PERMISSIVE_TEST','0').lower() in {'1','true','yes'}
        test_helpers = os.getenv('TEST_HELPERS_ENABLED','0').lower() in {'1','true','yes'}
        _lite = admin_permissive or test_helpers
    except Exception:
        _lite = False
    admin_api_key = _get_env('ADMIN_API_KEY')
    admin_ui_token = _get_env('ADMIN_UI_TOKEN')
    if _lite and not admin_api_key and not admin_ui_token:
        request.state.user = {'sub': 'admin-lite', 'role': 'admin'}
        return
    if admin_api_key:
        provided_key = request.headers.get('X-Admin-API-Key') or request.headers.get('x-admin-api-key')
        if provided_key and provided_key == admin_api_key:
            request.state.user = {'sub': 'admin-api-key', 'role': 'admin'}
            return

    # Try OIDC SSO validation first (Authorization Bearer or session cookie)
    auth = request.headers.get('Authorization') or ''
    if auth.startswith('Bearer '):
        provided = auth.split(' ', 1)[1].strip()
        # Validate lazily — synchronous callers will not await OIDC; try quick path
        # If validation fails, fall back to token check below
        try:
            import asyncio
            claims = asyncio.get_event_loop().run_until_complete(_validate_oidc_token(provided))
        except Exception:
            claims = None
        if claims:
            # attach user info to request.state for downstream use
            try:
                request.state.user = {'sub': claims.get('sub'), 'email': claims.get('email')}
            except Exception:
                request.state.user = {'sub': claims.get('sub')}
            return
    # Try admin token header
    provided_token = None
    if auth.startswith('Bearer '):
        provided_token = auth.split(' ', 1)[1].strip()
    else:
        provided_token = request.headers.get('X-Admin-Token') or request.headers.get('x-admin-token')
    if _validate_admin_token(provided_token):
        # stateless token; attach a minimal user
        request.state.user = {'sub': 'admin-token', 'role': 'admin'}
        return
    # Neither SSO nor token validated — deny access by default
    raise HTTPException(status_code=401, detail='unauthorized')
