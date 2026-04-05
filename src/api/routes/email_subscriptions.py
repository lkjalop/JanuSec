import os
import time
import logging
from fastapi import APIRouter, Request, HTTPException
from typing import Dict
from src.integrations.webhook_verifier import verify_jwt_with_jwks
from src.api.tenant_helpers import resolve_tenant_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/subscriptions", tags=["subscriptions"])

# In-memory subscription registry (demo). Production should persist.
_REGISTRY: Dict[str, Dict] = {}


@router.post('/msgraph/create')
def create_msgraph_subscription(tenant_id: str, payload: Dict, request: Request):
    tenant_id = resolve_tenant_id(request, tenant_id) or tenant_id
    # payload should include resource, changeType, notificationUrl, expiration
    key = f"msgraph:{tenant_id}:{payload.get('resource') or 'me/mailFolders/inbox/messages'}"
    sub = payload.copy()
    sub['created_at'] = int(time.time())
    sub['expires_at'] = int(time.time()) + int(payload.get('expiration', 3600))
    _REGISTRY[key] = sub
    return {'status': 'ok', 'subscription_key': key, 'expires_at': sub['expires_at']}


@router.post('/msgraph/renew')
def renew_msgraph_subscription(subscription_key: str, ttl: int = 3600):
    sub = _REGISTRY.get(subscription_key)
    if not sub:
        raise HTTPException(status_code=404, detail='subscription not found')
    sub['expires_at'] = int(time.time()) + int(ttl)
    return {'status': 'ok', 'expires_at': sub['expires_at']}


@router.post('/msgraph/callback')
async def msgraph_callback(request: Request):
    data = await request.json()
    # Validate subscription validation tokens per MS Graph if present
    if 'validationToken' in data:
        return data['validationToken']
    # Otherwise accept notifications
    # If notifications include clientState, optionally validate it matches expected secret
    try:
        client_state = None
        # Graph notifications are an array under 'value'
        for n in (data.get('value') or []):
            if isinstance(n, dict) and n.get('clientState'):
                client_state = n.get('clientState')
                break
        if client_state:
            expected = os.getenv('MSGRAPH_CLIENT_STATE')
            if expected and client_state != expected:
                raise HTTPException(status_code=403, detail='invalid_client_state')
    except HTTPException:
        raise
    except Exception:
        pass
    logger.info('Received msgraph notification: %s', data)
    return {'status': 'ok'}


@router.post('/gmail/callback')
async def gmail_callback(request: Request):
    # Gmail Pub/Sub pushes a JSON body; accept and log for demo
    data = await request.json()
    # First choice: JWKS-based JWT verification if configured
    try:
        jwks = os.getenv('GMAIL_PUBSUB_JWKS_URL')
        if jwks:
            # Pub/Sub includes a JWT in 'message.attributes.jwt' or Authorization header; check both
            token = None
            msg = data.get('message') or {}
            attrs = msg.get('attributes') or {}
            token = attrs.get('jwt') or attrs.get('authorization') or None
            if not token:
                # also allow bearer in top-level 'authorization' field
                token = data.get('authorization')
            if not token:
                raise HTTPException(status_code=403, detail='missing_jwt')
            # If token appears as 'Bearer <token>', strip prefix
            if isinstance(token, str) and token.lower().startswith('bearer '):
                token = token.split(' ', 1)[1]
            verify_jwt_with_jwks(token, jwks)
        else:
            # Simple verification: if push contains 'message' and attributes.verification_token, compare to env var
            msg = data.get('message') or {}
            attrs = msg.get('attributes') or {}
            vtok = attrs.get('verification_token') or os.getenv('GMAIL_PUBSUB_VERIFICATION_TOKEN')
            expected = os.getenv('GMAIL_PUBSUB_VERIFICATION_TOKEN')
            if expected and attrs.get('verification_token') != expected:
                raise HTTPException(status_code=403, detail='invalid_verification_token')
    except HTTPException:
        raise
    except Exception:
        # verification failed; log and reject
        logger.exception('Gmail pubsub verification failed')
        raise HTTPException(status_code=403, detail='jwt_verification_failed')
    logger.info('Received gmail pubsub push: %s', data)
    return {'status': 'ok'}
    return {'status': 'ok'}
