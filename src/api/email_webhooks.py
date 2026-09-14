from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any, Dict
from collections import deque

from fastapi import APIRouter, HTTPException, Request

router: APIRouter = APIRouter(prefix="/api/v1/email/webhooks", tags=["Email Webhooks"])

# In-memory Gmail history queue for follow-up sync (demo only)
_GMAIL_HISTORY_QUEUE: deque[dict[str, Any]] = deque(maxlen=1000)
_GMAIL_LAST_HISTORY: dict[str, Any] = {}
_GMAIL_HISTORY_HANDLERS: list[Any] = []


def _require_api_key(request: Request) -> None:
    hdr = request.headers.get('x-api-key') or request.headers.get('X-API-Key')
    dev_ok = os.getenv('ALLOW_DEV_API_KEY','1').lower() in {'1','true','yes'}
    if not hdr and not dev_ok:
        raise HTTPException(status_code=403, detail='api_key_required')


@router.post('/graph/subscribe')
async def graph_subscribe(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Create a Microsoft Graph subscription for user messages.

    Payload: { tenant_id, client_id, client_secret, user_id, notification_url }
    If omitted, env vars MS_GRAPH_TENANT_ID/MS_GRAPH_CLIENT_ID/MS_GRAPH_CLIENT_SECRET/GRAPH_WEBHOOK_NOTIFY_URL are used.
    """
    _require_api_key(request)
    tenant_id = payload.get('tenant_id') or os.getenv('MS_GRAPH_TENANT_ID')
    client_id = payload.get('client_id') or os.getenv('MS_GRAPH_CLIENT_ID')
    client_secret = payload.get('client_secret') or os.getenv('MS_GRAPH_CLIENT_SECRET')
    user_id = payload.get('user_id') or os.getenv('MS_GRAPH_USER_ID')
    notify_url = payload.get('notification_url') or os.getenv('GRAPH_WEBHOOK_NOTIFY_URL')
    if not all([tenant_id, client_id, client_secret, user_id, notify_url]):
        raise HTTPException(status_code=400, detail='missing_credentials')
    try:
        from src.integrations.auth.oauth_providers import MSALProvider  # type: ignore
    except Exception:
        try:
            from integrations.auth.oauth_providers import MSALProvider  # type: ignore
        except Exception:
            raise HTTPException(status_code=500, detail='msal_provider_missing')
    # Acquire token
    try:
        oauth = MSALProvider(client_id=str(client_id), client_secret=str(client_secret), tenant_id=str(tenant_id))
        token = await oauth.get_access_token()
    except Exception:
        raise HTTPException(status_code=502, detail='token_acquisition_failed')
    # Build subscription request
    resource = f"/users/{user_id}/messages"
    expires = (datetime.utcnow() + timedelta(hours=1)).isoformat() + 'Z'  # demo: 1h
    body = {
        'changeType': 'created,updated',
        'notificationUrl': str(notify_url),
        'resource': resource,
        'expirationDateTime': expires,
        'clientState': 'janusec-demo',
        'includeResourceData': False,
    }
    try:
        import httpx
        headers = { 'Authorization': f'Bearer {token}', 'Content-Type': 'application/json' }
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post('https://graph.microsoft.com/v1.0/subscriptions', json=body, headers=headers)
            if resp.status_code >= 400:
                raise HTTPException(status_code=resp.status_code, detail=f'subscribe_failed:{resp.text[:200]}')
            data = resp.json()
            return { 'created': True, 'subscription': data }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f'graph_error:{exc}')


@router.post('/gmail/subscribe')
async def gmail_subscribe(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Placeholder for Gmail push subscription via Pub/Sub.

    Real implementation requires Google Cloud Pub/Sub and topic/subscription setup.
    Returns 501 with guidance unless GMAIL_PUSH_ENABLED=true.
    """
    _require_api_key(request)
    if os.getenv('GMAIL_PUSH_ENABLED','0').lower() not in {'1','true','yes'}:
        raise HTTPException(status_code=501, detail='gmail_push_not_configured')
    # TODO: implement Pub/Sub topic and watch request orchestration
    return { 'status': 'pending', 'detail': 'gmail_push_scaffold' }


@router.post('/gmail/watch')
async def gmail_watch(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Initiate Gmail push notifications via Watch.

    Requires: Google OAuth refresh token and configured Pub/Sub topic.
    Body/env:
      - user_email (or GMAIL_USER_EMAIL)
      - topic_name (or GMAIL_TOPIC_NAME)
      - label_ids (optional)
      - client_id/client_secret/refresh_token (or env GMAIL_CLIENT_ID/GMAIL_CLIENT_SECRET/GMAIL_REFRESH_TOKEN)
    """
    _require_api_key(request)
    user_email = payload.get('user_email') or os.getenv('GMAIL_USER_EMAIL')
    topic = payload.get('topic_name') or os.getenv('GMAIL_TOPIC_NAME')
    label_ids = payload.get('label_ids') or None
    client_id = payload.get('client_id') or os.getenv('GMAIL_CLIENT_ID')
    client_secret = payload.get('client_secret') or os.getenv('GMAIL_CLIENT_SECRET')
    refresh_token = payload.get('refresh_token') or os.getenv('GMAIL_REFRESH_TOKEN')
    if not all([user_email, topic, client_id, client_secret, refresh_token]):
        raise HTTPException(status_code=400, detail='missing_gmail_watch_config')
    try:
        from src.integrations.auth.oauth_providers import GoogleOAuthProvider  # type: ignore
    except Exception:
        try:
            from integrations.auth.oauth_providers import GoogleOAuthProvider  # type: ignore
        except Exception:
            raise HTTPException(status_code=500, detail='google_provider_missing')
    try:
        oauth = GoogleOAuthProvider(client_id=str(client_id), client_secret=str(client_secret), refresh_token=str(refresh_token))
        token = await oauth.get_access_token()
    except Exception:
        raise HTTPException(status_code=502, detail='token_acquisition_failed')
    body = { 'topicName': str(topic) }
    if label_ids:
        body['labelIds'] = label_ids
    try:
        import httpx
        headers = { 'Authorization': f'Bearer {token}', 'Content-Type': 'application/json' }
        url = f'https://gmail.googleapis.com/gmail/v1/users/{user_email}/watch'
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, json=body, headers=headers)
            if resp.status_code >= 400:
                raise HTTPException(status_code=resp.status_code, detail=f'watch_failed:{resp.text[:200]}')
            data = resp.json()
            return { 'created': True, 'watch': data }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f'gmail_error:{exc}')


@router.post('/gmail/notifications')
async def gmail_notifications(payload: Dict[str, Any], request: Request) -> Dict[str, Any]:
    """Receive Gmail Pub/Sub push notifications and enqueue historyId.

    Expected payload shape (Pub/Sub push):
    { "message": { "data": base64(JSON{"emailAddress":"...","historyId":"..."}) } }
    """
    # Allow unauthenticated Pub/Sub when demo flag set; else require API key
    if os.getenv('GMAIL_PUSH_DEMO','0').lower() not in {'1','true','yes'}:
        _require_api_key(request)
    try:
        msg = (payload.get('message') or {})
        data_b64 = msg.get('data')
        if not isinstance(data_b64, str):
            raise HTTPException(status_code=400, detail='missing_data')
        import base64, json, time as _t
        decoded = base64.b64decode(data_b64)
        j = json.loads(decoded or b'{}')
        email_addr = j.get('emailAddress') or 'me'
        history_id = str(j.get('historyId') or '')
        if not history_id:
            raise HTTPException(status_code=400, detail='missing_history_id')
        item = { 'email': email_addr, 'historyId': history_id, 'ts': int(_t.time()) }
        _GMAIL_HISTORY_QUEUE.append(item)
        _GMAIL_LAST_HISTORY[email_addr] = item
        # Invoke any registered handlers (best-effort)
        try:
            for fn in list(_GMAIL_HISTORY_HANDLERS):
                try:
                    res = fn(item)
                    if hasattr(res, '__await__'):  # allow async handlers
                        import asyncio
                        await res
                except Exception:
                    pass
        except Exception:
            pass
        return { 'received': True, 'queued': True, 'size': len(_GMAIL_HISTORY_QUEUE), 'item': item }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail='invalid_payload')


@router.get('/gmail/history/pending')
async def gmail_history_pending(limit: int = 50, pop: bool = False) -> Dict[str, Any]:
    """Inspect (and optionally pop) pending Gmail history items in the queue."""
    items: list[dict[str, Any]] = []
    try:
        import itertools
        if pop:
            for _ in range(max(0, int(limit))):
                try:
                    items.append(_GMAIL_HISTORY_QUEUE.popleft())
                except Exception:
                    break
        else:
            # snapshot without removing
            items = list(itertools.islice(_GMAIL_HISTORY_QUEUE, 0, max(0, int(limit))))
    except Exception:
        items = []
    return { 'size': len(_GMAIL_HISTORY_QUEUE), 'items': items, 'last': _GMAIL_LAST_HISTORY }


def register_history_handler(handler: Any) -> None:
    """Register a handler function to process history items as they arrive.

    Handlers may be sync or async callables accepting a single item dict.
    """
    try:
        _GMAIL_HISTORY_HANDLERS.append(handler)
    except Exception:
        pass


__all__ = ['router']
