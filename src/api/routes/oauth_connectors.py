from __future__ import annotations

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional
import logging

from src.integrations.tenant_store import TenantStore
from src.integrations.auth.msal_provider import MSALProvider
from src.integrations.auth.google_oauth_provider import GoogleOAuthProvider
from src.core.config import get_settings
from ..tenant_helpers import resolve_tenant_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/integrations/oauth")


@router.get('/start')
async def oauth_start(provider: str, tenant_id: Optional[str] = None, request: Request = None):
    """Initiate OAuth flow and redirect user to provider consent page.

    Query params:
    - provider: 'msal' or 'google'
    - tenant_id: optional tenant identifier (used to persist tokens)
    """
    t = resolve_tenant_id(request, tenant_id) or 'default'
    settings = get_settings()
    redirect_base = settings.get('OAUTH_REDIRECT_BASE') if isinstance(settings, dict) else None
    # Build redirect URI to callback endpoint
    # If settings provide a base, use it; else derive from request
    if redirect_base:
        redirect_uri = redirect_base.rstrip('/') + '/api/v1/integrations/oauth/callback'
    else:
        url = request.url
        redirect_uri = f"{url.scheme}://{url.hostname}:{url.port or ''}".rstrip(':') + '/api/v1/integrations/oauth/callback'

    try:
        if provider.lower() in ('msal', 'microsoft'):
            client_id = settings.get('MSAL_CLIENT_ID') if isinstance(settings, dict) else None
            client_secret = settings.get('MSAL_CLIENT_SECRET') if isinstance(settings, dict) else None
            if not client_id or not client_secret:
                raise HTTPException(status_code=500, detail='MSAL client credentials not configured')
            p = MSALProvider(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri)
            url = p.get_authorization_url(state=t)
            return RedirectResponse(url)
        elif provider.lower() in ('google', 'gmail'):
            client_id = settings.get('GOOGLE_CLIENT_ID') if isinstance(settings, dict) else None
            client_secret = settings.get('GOOGLE_CLIENT_SECRET') if isinstance(settings, dict) else None
            if not client_id or not client_secret:
                raise HTTPException(status_code=500, detail='Google client credentials not configured')
            p = GoogleOAuthProvider(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri)
            url = p.get_authorization_url(state=t)
            return RedirectResponse(url)
        else:
            raise HTTPException(status_code=400, detail='unsupported provider')
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception('oauth_start error')
        raise HTTPException(status_code=500, detail='internal_error')


@router.get('/callback')
async def oauth_callback(code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None, request: Request = None):
    """Handle OAuth callback. Exchanges code for tokens and persists them under tenant (state).

    Returns JSON status and tenant id.
    """
    if error:
        return JSONResponse({'status': 'error', 'error': error}, status_code=400)
    if not code:
        raise HTTPException(status_code=400, detail='missing_code')
    tenant_id = resolve_tenant_id(request, state or 'default') or 'default'
    settings = get_settings()
    # Try both providers: attempt MSAL exchange first, then Google if MSAL fails.
    try:
        # MSAL attempt
        try:
            client_id = settings.get('MSAL_CLIENT_ID') if isinstance(settings, dict) else None
            client_secret = settings.get('MSAL_CLIENT_SECRET') if isinstance(settings, dict) else None
            if client_id and client_secret:
                redirect_base = settings.get('OAUTH_REDIRECT_BASE') if isinstance(settings, dict) else None
                if redirect_base:
                    redirect_uri = redirect_base.rstrip('/') + '/api/v1/integrations/oauth/callback'
                else:
                    url = request.url
                    redirect_uri = f"{url.scheme}://{url.hostname}:{url.port or ''}".rstrip(':') + '/api/v1/integrations/oauth/callback'
                p = MSALProvider(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri)
                token = p.exchange_code(code)
                # persist client creds on tenant tokens for future refreshes
                try:
                    ts = TenantStore()
                    token['client_id'] = client_id
                    token['client_secret'] = client_secret
                    ts.save_tokens(tenant_id, token)
                except Exception:
                    logger.debug('Failed to persist msal tokens to tenant store')
                return JSONResponse({'status': 'ok', 'tenant': tenant_id})
        except Exception:
            logger.debug('MSAL exchange failed; trying Google')
        # Google attempt
        try:
            client_id = settings.get('GOOGLE_CLIENT_ID') if isinstance(settings, dict) else None
            client_secret = settings.get('GOOGLE_CLIENT_SECRET') if isinstance(settings, dict) else None
            if client_id and client_secret:
                redirect_base = settings.get('OAUTH_REDIRECT_BASE') if isinstance(settings, dict) else None
                if redirect_base:
                    redirect_uri = redirect_base.rstrip('/') + '/api/v1/integrations/oauth/callback'
                else:
                    url = request.url
                    redirect_uri = f"{url.scheme}://{url.hostname}:{url.port or ''}".rstrip(':') + '/api/v1/integrations/oauth/callback'
                p = GoogleOAuthProvider(client_id=client_id, client_secret=client_secret, redirect_uri=redirect_uri)
                token = p.exchange_code(code, tenant_id=tenant_id)
                return JSONResponse({'status': 'ok', 'tenant': tenant_id})
        except Exception:
            logger.exception('Google exchange failed')
        raise HTTPException(status_code=500, detail='exchange_failed')
    except HTTPException:
        raise
    except Exception:
        logger.exception('oauth_callback unexpected')
        raise HTTPException(status_code=500, detail='internal_error')


__all__ = ['router']
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional
import os
import time
import logging

from integrations.msgraph_connector import MSGraphConnector
from integrations.gmail_connector import GmailConnector
from integrations.tenant_store import TenantStore
from ..tenant_helpers import resolve_tenant_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/integrations/oauth", tags=["oauth"])


def _tenant_id_from_request(request: Request) -> str:
    tid = request.query_params.get('tenant_id') or request.headers.get('x-tenant-id') or os.getenv('DEFAULT_TENANT','default')
    return resolve_tenant_id(request, tid) or tid


@router.get('/msgraph/start')
async def msgraph_start(request: Request, redirect: Optional[str] = None, tenant: Optional[str] = None):
    tid = _tenant_id_from_request(request)
    if tenant:
        tid = resolve_tenant_id(request, tenant) or tenant
    # Use env vars for client credentials by default
    client_id = os.getenv('MSGRAPH_CLIENT_ID')
    client_secret = os.getenv('MSGRAPH_CLIENT_SECRET')
    redirect_uri = os.getenv('MSGRAPH_REDIRECT') or (request.base_url._url + 'api/v1/integrations/oauth/msgraph/callback')
    if not client_id or not client_secret:
        raise HTTPException(status_code=400, detail='MSGRAPH_CLIENT_ID and MSGRAPH_CLIENT_SECRET must be configured in env for demo start')
    conn = MSGraphConnector(client_id, client_secret, redirect_uri)
    state = f"tenant:{tid}:{int(time.time())}"
    auth_url = conn.get_authorization_url(state=state)
    if redirect and redirect.lower() in ('1','true','yes'):
        return RedirectResponse(auth_url)
    return JSONResponse({'auth_url': auth_url, 'state': state, 'tenant_id': tid})


@router.get('/msgraph/callback')
async def msgraph_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None):
    tid = _tenant_id_from_request(request)
    client_id = os.getenv('MSGRAPH_CLIENT_ID')
    client_secret = os.getenv('MSGRAPH_CLIENT_SECRET')
    redirect_uri = os.getenv('MSGRAPH_REDIRECT') or (request.base_url._url + 'api/v1/integrations/oauth/msgraph/callback')
    if not code:
        raise HTTPException(status_code=400, detail='Missing code')
    conn = MSGraphConnector(client_id, client_secret, redirect_uri)
    token_payload = conn.exchange_code(code)
    # compute expires_at
    if token_payload.get('expires_in'):
        token_payload['expires_at'] = int(time.time()) + int(token_payload.get('expires_in'))
    # persist client_id/secret for demo convenience
    token_payload['client_id'] = client_id
    token_payload['client_secret'] = client_secret
    store = TenantStore()
    store.save_tokens(tid, token_payload)
    logger.info('Saved MS Graph tokens for tenant %s', tid)
    return JSONResponse({'status': 'ok', 'tenant_id': tid})


@router.get('/gmail/start')
async def gmail_start(request: Request, redirect: Optional[str] = None, tenant: Optional[str] = None):
    tid = _tenant_id_from_request(request)
    if tenant:
        tid = resolve_tenant_id(request, tenant) or tenant
    client_id = os.getenv('GMAIL_CLIENT_ID')
    client_secret = os.getenv('GMAIL_CLIENT_SECRET')
    redirect_uri = os.getenv('GMAIL_REDIRECT') or (request.base_url._url + 'api/v1/integrations/oauth/gmail/callback')
    if not client_id or not client_secret:
        raise HTTPException(status_code=400, detail='GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET must be configured in env for demo start')
    conn = GmailConnector(client_id, client_secret, redirect_uri)
    state = f"tenant:{tid}:{int(time.time())}"
    auth_url = conn.get_authorization_url(state=state)
    if redirect and redirect.lower() in ('1','true','yes'):
        return RedirectResponse(auth_url)
    return JSONResponse({'auth_url': auth_url, 'state': state, 'tenant_id': tid})


@router.get('/gmail/callback')
async def gmail_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None):
    tid = _tenant_id_from_request(request)
    client_id = os.getenv('GMAIL_CLIENT_ID')
    client_secret = os.getenv('GMAIL_CLIENT_SECRET')
    redirect_uri = os.getenv('GMAIL_REDIRECT') or (request.base_url._url + 'api/v1/integrations/oauth/gmail/callback')
    if not code:
        raise HTTPException(status_code=400, detail='Missing code')
    conn = GmailConnector(client_id, client_secret, redirect_uri)
    token_payload = conn.exchange_code(code)
    if token_payload.get('expires_in'):
        token_payload['expires_at'] = int(time.time()) + int(token_payload.get('expires_in'))
    token_payload['client_id'] = client_id
    token_payload['client_secret'] = client_secret
    store = TenantStore()
    store.save_tokens(tid, token_payload)
    logger.info('Saved Gmail tokens for tenant %s', tid)
    return JSONResponse({'status': 'ok', 'tenant_id': tid})
