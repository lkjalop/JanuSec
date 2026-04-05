from __future__ import annotations
import os, time
from typing import List, Dict, Any
from .base import EventCollector

import logging
try:
    import msal
except Exception:
    msal = None

try:
    import requests
except Exception:
    requests = None

try:
    from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
except Exception:
    def retry(*args, **kwargs):
        def decorator(f):
            return f
        return decorator


    def stop_after_attempt(n):
        return None

    def wait_exponential(**kwargs):
        return None

    def retry_if_exception_type(exc):
        return (lambda e: True)

    try:
        from src.security.signature_helpers import preserve_signature
        try:
            preserve_signature(retry, retry)
        except Exception:
            import inspect as _inspect
            try:
                retry.__signature__ = _inspect.signature(retry)
            except Exception:
                pass
    except Exception:
        try:
            import inspect as _inspect
            retry.__signature__ = _inspect.signature(retry)
        except Exception:
            pass

import datetime
try:
    from src.integrations.ms_graph_connector import MicrosoftGraphConnector
except Exception:
    MicrosoftGraphConnector = None


class O365EmailCollector(EventCollector):
    source = "o365"

    def __init__(self):
        self._tenant = os.getenv("O365_TENANT")
        self._client = os.getenv("O365_CLIENT_ID")
        self._secret = os.getenv("O365_CLIENT_SECRET")
        self._token = None
        self._session = None
        self._ms_graph = None
        if self._tenant and self._client and self._secret and msal is not None and requests is not None:
            try:
                self._app = msal.ConfidentialClientApplication(
                    self._client,
                    authority=f"https://login.microsoftonline.com/{self._tenant}",
                    client_credential=self._secret
                )
                self._token = self._app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
                self._session = requests.Session()
            except Exception as e:
                logging.error(f"Failed to initialize MSAL client: {e}")
                self._app = None
                self._session = None
        # Prefer the new MicrosoftGraphConnector when available
        try:
            if MicrosoftGraphConnector is not None:
                self._ms_graph = MicrosoftGraphConnector(tenant_id=self._tenant, client_id=self._client, client_secret=self._secret)
        except Exception:
            self._ms_graph = None

    def fetch_events(self, since_ts: float) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        # If ms_graph connector is available, use it (it handles pagination and checkpointing)
        if self._ms_graph is not None:
            try:
                import asyncio
                evs, cursor = asyncio.run(self._ms_graph.fetch_since(None, limit=200))
                try:
                    if cursor:
                        asyncio.run(self._ms_graph.ack(cursor))
                except Exception:
                    pass
                return [e.get('raw') if isinstance(e, dict) and 'raw' in e else e for e in evs]
            except Exception:
                logging.debug('MS Graph connector fetch failed; falling back to direct MSAL client')
        if not (self._app and self._session):
            return []

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10),
               retry=retry_if_exception_type(Exception))
        def get_o365_messages():
            # Use MS Graph API: /users/{id}/messages or /me/messages
            # For demo, fetch messages for a test user
            user_id = os.getenv('O365_USER_ID')
            if not user_id:
                logging.error("O365_USER_ID not set")
                return []
            url = f"https://graph.microsoft.com/v1.0/users/{user_id}/messages"
            token = self._app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
            if "access_token" not in token:
                logging.error(f"O365 token error: {token}")
                return []
            headers = {"Authorization": f"Bearer {token['access_token']}", "Accept": "application/json"}
            params = {
                "$filter": f"receivedDateTime ge {datetime.datetime.utcfromtimestamp(since_ts).isoformat()}Z",
                "$top": 100
            }
            next_url = url
            while next_url:
                resp = self._session.get(next_url, headers=headers, params=params if next_url == url else None, timeout=15)
                if resp.status_code != 200:
                    logging.error(f"O365 messages fetch failed: {resp.status_code} {resp.text}")
                    break
                data = resp.json()
                for msg in data.get('value', []):
                    events.append(msg)
                next_url = data.get('@odata.nextLink')
            return events

        try:
            return get_o365_messages()
        except Exception as e:
            logging.error(f"O365 fetch_events error: {e}")
            return []


__all__ = ["O365EmailCollector"]